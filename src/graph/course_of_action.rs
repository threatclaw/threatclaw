//! STIX 2.1 Course of Action — automated remediation playbooks.
//!
//! When a CVE or attack technique is detected, ThreatClaw looks up
//! the associated Course of Action in the graph and delivers it
//! alongside the alert notification.
//!
//! CoA sources: MITRE ATT&CK mitigations, CISA KEV required actions,
//! and RSSI-defined custom playbooks.

use crate::db::Database;
use crate::graph::threat_graph::{mutate, query};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// STIX 2.1 Course of Action object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CourseOfAction {
    pub id: String,
    pub name: String,
    pub description: String,
    /// "mitre_mitigation" | "kev_action" | "custom_playbook"
    pub action_type: String,
    /// Steps to follow (ordered).
    pub steps: Vec<String>,
    /// Related MITRE mitigation ID (e.g., M1036).
    pub mitre_id: Option<String>,
    /// Estimated time to implement.
    pub estimated_minutes: Option<u32>,
}

/// Upsert a Course of Action node in the graph.
pub async fn upsert_coa(store: &dyn Database, coa: &CourseOfAction) {
    let steps_json = serde_json::to_string(&coa.steps).unwrap_or_default();
    let cypher = format!(
        "MERGE (c:CourseOfAction {{id: '{}'}}) \
         SET c.name = '{}', c.description = '{}', c.action_type = '{}', \
         c.steps = '{}', c.mitre_id = '{}', c.estimated_minutes = {} \
         RETURN c",
        esc(&coa.id),
        esc(&coa.name),
        esc(&coa.description),
        esc(&coa.action_type),
        esc(&steps_json),
        esc(coa.mitre_id.as_deref().unwrap_or("")),
        coa.estimated_minutes.unwrap_or(0)
    );
    mutate(store, &cypher).await;
}

/// Link a CoA to a CVE: CourseOfAction -[:MITIGATES]-> CVE
pub async fn link_coa_to_cve(store: &dyn Database, coa_id: &str, cve_id: &str) {
    let cypher = format!(
        "MATCH (c:CourseOfAction {{id: '{}'}}), (v:CVE {{id: '{}'}}) \
         MERGE (c)-[:MITIGATES]->(v)",
        esc(coa_id),
        esc(cve_id)
    );
    mutate(store, &cypher).await;
}

/// Link a CoA to a MITRE Technique: CourseOfAction -[:MITIGATES]-> Technique
pub async fn link_coa_to_technique(store: &dyn Database, coa_id: &str, mitre_id: &str) {
    let cypher = format!(
        "MATCH (c:CourseOfAction {{id: '{}'}}), (t:Technique {{mitre_id: '{}'}}) \
         MERGE (c)-[:MITIGATES]->(t)",
        esc(coa_id),
        esc(mitre_id)
    );
    mutate(store, &cypher).await;
}

/// Find all Courses of Action that mitigate a specific CVE.
pub async fn find_coa_for_cve(store: &dyn Database, cve_id: &str) -> Vec<serde_json::Value> {
    query(
        store,
        &format!(
            "MATCH (c:CourseOfAction)-[:MITIGATES]->(v:CVE {{id: '{}'}}) \
         RETURN c.id, c.name, c.description, c.steps, c.action_type, c.estimated_minutes \
         ORDER BY c.action_type",
            esc(cve_id)
        ),
    )
    .await
}

/// Find all Courses of Action for a MITRE technique.
pub async fn find_coa_for_technique(
    store: &dyn Database,
    mitre_id: &str,
) -> Vec<serde_json::Value> {
    query(
        store,
        &format!(
            "MATCH (c:CourseOfAction)-[:MITIGATES]->(t:Technique {{mitre_id: '{}'}}) \
         RETURN c.id, c.name, c.description, c.steps, c.action_type",
            esc(mitre_id)
        ),
    )
    .await
}

/// Find all CoAs relevant to an asset (via CVEs affecting it + techniques used against it).
pub async fn find_coa_for_asset(store: &dyn Database, asset_id: &str) -> Vec<serde_json::Value> {
    query(
        store,
        &format!(
            "MATCH (c:CourseOfAction)-[:MITIGATES]->(v:CVE)-[:AFFECTS]->(a:Asset {{id: '{}'}}) \
         RETURN DISTINCT c.id, c.name, c.description, c.steps, c.action_type, v.id AS cve_id \
         ORDER BY c.action_type",
            esc(asset_id)
        ),
    )
    .await
}

/// Seed default MITRE ATT&CK mitigations as CoA nodes.
/// Maps common techniques to actionable mitigations.
pub async fn seed_default_mitigations(store: &dyn Database) {
    let defaults = vec![
        CourseOfAction {
            id: "coa--mitre-m1036".into(),
            name: "Account Use Policies".into(),
            description: "Configurer les politiques d'utilisation des comptes : complexité mot de passe, verrouillage après N tentatives, MFA obligatoire".into(),
            action_type: "mitre_mitigation".into(),
            steps: vec![
                "Activer le verrouillage de compte après 5 tentatives échouées".into(),
                "Imposer MFA sur tous les comptes admin".into(),
                "Configurer une complexité minimum de 12 caractères".into(),
                "Auditer les comptes de service sans MFA".into(),
            ],
            mitre_id: Some("M1036".into()),
            estimated_minutes: Some(60),
        },
        CourseOfAction {
            id: "coa--mitre-m1035".into(),
            name: "Limit Access to Resource Over Network".into(),
            description: "Restreindre l'accès réseau aux services critiques : segmentation, firewall, ACLs".into(),
            action_type: "mitre_mitigation".into(),
            steps: vec![
                "Segmenter le réseau (VLAN prod vs dev vs DMZ)".into(),
                "Bloquer SSH depuis internet (uniquement VPN)".into(),
                "Configurer des ACLs par service et par port".into(),
                "Limiter les connexions SMB entre segments".into(),
            ],
            mitre_id: Some("M1035".into()),
            estimated_minutes: Some(120),
        },
        CourseOfAction {
            id: "coa--mitre-m1051".into(),
            name: "Update Software".into(),
            description: "Mettre à jour les logiciels vulnérables, en priorité ceux avec EPSS > 0.5 ou dans CISA KEV".into(),
            action_type: "mitre_mitigation".into(),
            steps: vec![
                "Identifier les CVEs sur l'asset via ThreatClaw".into(),
                "Prioriser par EPSS et KEV status".into(),
                "Tester le patch en environnement staging".into(),
                "Appliquer le patch en production avec rollback plan".into(),
                "Vérifier le scan post-patch".into(),
            ],
            mitre_id: Some("M1051".into()),
            estimated_minutes: Some(30),
        },
        CourseOfAction {
            id: "coa--mitre-m1049".into(),
            name: "Antivirus/Antimalware".into(),
            description: "Déployer et maintenir une solution antimalware sur tous les endpoints".into(),
            action_type: "mitre_mitigation".into(),
            steps: vec![
                "Vérifier que l'antimalware est actif sur tous les endpoints".into(),
                "Mettre à jour les signatures".into(),
                "Scanner les fichiers suspects identifiés par ThreatClaw".into(),
                "Isoler et quarantainer les menaces détectées".into(),
            ],
            mitre_id: Some("M1049".into()),
            estimated_minutes: Some(15),
        },
        CourseOfAction {
            id: "coa--mitre-m1037".into(),
            name: "Filter Network Traffic".into(),
            description: "Filtrer le trafic réseau pour bloquer les communications C2 et l'exfiltration DNS".into(),
            action_type: "mitre_mitigation".into(),
            steps: vec![
                "Bloquer les IPs malveillantes identifiées (GreyNoise/CrowdSec)".into(),
                "Configurer le DNS sinkhole pour les domaines C2".into(),
                "Limiter le trafic DNS sortant aux résolveurs internes".into(),
                "Monitorer les connexions sortantes inhabituelles".into(),
            ],
            mitre_id: Some("M1037".into()),
            estimated_minutes: Some(45),
        },
    ];

    // Map techniques to mitigations
    let technique_map: &[(&str, &str)] = &[
        ("T1110", "coa--mitre-m1036"),     // Brute Force → Account Policies
        ("T1078", "coa--mitre-m1036"),     // Valid Accounts → Account Policies
        ("T1021", "coa--mitre-m1035"),     // Remote Services → Limit Network
        ("T1190", "coa--mitre-m1051"),     // Exploit Public-Facing → Update Software
        ("T1068", "coa--mitre-m1051"),     // Priv Escalation → Update Software
        ("T1204", "coa--mitre-m1049"),     // User Execution → Antimalware
        ("T1071", "coa--mitre-m1037"),     // Application Layer Protocol → Filter Traffic
        ("T1071.004", "coa--mitre-m1037"), // DNS → Filter Traffic
        ("T1041", "coa--mitre-m1037"),     // Exfiltration → Filter Traffic
        ("T1059", "coa--mitre-m1049"),     // Command Interpreter → Antimalware
        ("T1003", "coa--mitre-m1036"),     // Credential Dumping → Account Policies
        ("T1566", "coa--mitre-m1049"),     // Phishing → Antimalware
    ];

    for coa in &defaults {
        upsert_coa(store, coa).await;
    }

    for (technique, coa_id) in technique_map {
        link_coa_to_technique(store, coa_id, technique).await;
    }

    tracing::info!(
        "COA: Seeded {} default mitigations with {} technique mappings",
        defaults.len(),
        technique_map.len()
    );
}

/// Format CoAs for notification/HITL message.
pub fn format_coa_for_alert(coas: &[serde_json::Value]) -> String {
    if coas.is_empty() {
        return String::new();
    }

    let mut out = String::from("Playbook recommandé :\n");
    for (i, coa) in coas.iter().enumerate().take(3) {
        let r = &coa["result"];
        let name = r["c.name"].as_str().unwrap_or("?");
        let steps_str = r["c.steps"].as_str().unwrap_or("[]");
        let steps: Vec<String> = serde_json::from_str(steps_str).unwrap_or_default();

        out.push_str(&format!("\n{}. {}\n", i + 1, name));
        for (j, step) in steps.iter().enumerate().take(4) {
            out.push_str(&format!("   {}. {}\n", j + 1, step));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coa_struct() {
        let coa = CourseOfAction {
            id: "coa--test".into(),
            name: "Test".into(),
            description: "A test CoA".into(),
            action_type: "custom_playbook".into(),
            steps: vec!["Step 1".into(), "Step 2".into()],
            mitre_id: None,
            estimated_minutes: Some(30),
        };
        assert_eq!(coa.steps.len(), 2);
    }

    #[test]
    fn test_format_coa_empty() {
        assert_eq!(format_coa_for_alert(&[]), "");
    }

    #[test]
    fn test_format_coa_with_data() {
        let coas = vec![json!({
            "result": {
                "c.name": "Update Software",
                "c.steps": "[\"Patch nginx\",\"Test en staging\"]"
            }
        })];
        let formatted = format_coa_for_alert(&coas);
        assert!(formatted.contains("Update Software"));
        assert!(formatted.contains("Patch nginx"));
    }
}
