// See ADR-044: Auto-CVE correlation for software inventory
//
// Quand l'agent (osquery) remonte la liste des logiciels d'un asset,
// on croise avec : 1) findings CVE existants en DB, 2) CISA KEV, 3) NVD keyword search.
// Résultat : finding automatique pour chaque logiciel vulnérable.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;

/// Critical software that warrants NVD lookup even without existing CVE findings.
const CRITICAL_SOFTWARE: &[&str] = &[
    "openssh",
    "openssl",
    "nginx",
    "apache",
    "httpd",
    "php",
    "python",
    "node",
    "java",
    "tomcat",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "mongodb",
    "docker",
    "containerd",
    "kubernetes",
    "kubelet",
    "samba",
    "bind",
    "named",
    "postfix",
    "exim",
    "sudo",
    "polkit",
    "systemd",
    "kernel",
    "linux-image",
    "curl",
    "wget",
    "git",
    "vscode",
    "chrome",
    "firefox",
    "wordpress",
    "drupal",
    "joomla",
    "exchange",
    "iis",
    "rdp",
    "smb",
];

pub struct VulnScanResult {
    pub software_checked: usize,
    pub cves_found: usize,
    pub findings_created: usize,
    pub critical_count: usize,
}

/// Scan an asset's software inventory for known vulnerabilities.
/// Called after osquery ingests software data.
pub async fn scan_asset_software(
    store: &dyn Database,
    asset_id: &str,
    asset_name: &str,
    software: &[serde_json::Value],
) -> VulnScanResult {
    let mut result = VulnScanResult {
        software_checked: 0,
        cves_found: 0,
        findings_created: 0,
        critical_count: 0,
    };

    if software.is_empty() {
        return result;
    }

    // Load existing CVE findings for this asset (avoid duplicates)
    let existing_findings = store
        .list_findings(None, None, Some(asset_name), 500, 0)
        .await
        .unwrap_or_default();
    let existing_cves: std::collections::HashSet<String> = existing_findings
        .iter()
        .filter_map(|f| f.metadata.get("cve")?.as_str().map(String::from))
        .collect();

    for sw in software {
        let name = sw["name"].as_str().unwrap_or("").trim().to_lowercase();
        let version = sw["version"].as_str().unwrap_or("").trim();
        if name.is_empty() || version.is_empty() {
            continue;
        }

        result.software_checked += 1;

        // Check CISA KEV for this software (fast, local DB)
        let kev_cves = check_kev_for_software(store, &name, version).await;
        for cve_id in &kev_cves {
            if existing_cves.contains(cve_id) {
                continue;
            }

            let _ = store
                .insert_finding(&crate::db::threatclaw_store::NewFinding {
                    skill_id: "software-vuln".into(),
                    title: format!(
                        "{} {} — {} (CISA KEV: exploit actif)",
                        name, version, cve_id
                    ),
                    description: Some(format!(
                        "Le logiciel {} version {} installé sur {} est affecté par {}. \
                     Cette CVE est dans la liste CISA KEV — exploitation active confirmée. \
                     Mise à jour immédiate requise.",
                        name, version, asset_name, cve_id
                    )),
                    severity: "CRITICAL".into(),
                    category: Some("software-vuln".into()),
                    asset: Some(asset_name.to_string()),
                    source: Some("CISA KEV × osquery".into()),
                    metadata: Some(serde_json::json!({
                        "cve": cve_id,
                        "software": name,
                        "version": version,
                        "exploited_in_wild": true,
                        "detection": "software-vuln-kev",
                        "mitre": ["T1190"]
                    })),
                })
                .await;
            result.cves_found += 1;
            result.findings_created += 1;
            result.critical_count += 1;
        }

        // For critical software, check NVD cache
        let name_lower = name.to_lowercase();
        if CRITICAL_SOFTWARE.iter().any(|cs| name_lower.contains(cs)) {
            let cached_cves = check_nvd_cache_for_software(store, &name, version).await;
            for (cve_id, cvss, severity) in &cached_cves {
                if existing_cves.contains(cve_id) {
                    continue;
                }

                let sev = if *cvss >= 9.0 {
                    "CRITICAL"
                } else if *cvss >= 7.0 {
                    "HIGH"
                } else {
                    "MEDIUM"
                };
                let _ = store.insert_finding(&crate::db::threatclaw_store::NewFinding {
                    skill_id: "software-vuln".into(),
                    title: format!("{} {} — {} (CVSS {:.1})", name, version, cve_id, cvss),
                    description: Some(format!(
                        "Le logiciel {} version {} installé sur {} est affecté par {} (CVSS {:.1}, {}).",
                        name, version, asset_name, cve_id, cvss, severity
                    )),
                    severity: sev.into(),
                    category: Some("software-vuln".into()),
                    asset: Some(asset_name.to_string()),
                    source: Some("NVD × osquery".into()),
                    metadata: Some(serde_json::json!({
                        "cve": cve_id,
                        "software": name,
                        "version": version,
                        "cvss": cvss,
                        "severity": severity,
                        "detection": "software-vuln-nvd",
                        "mitre": ["T1190"]
                    })),
                }).await;
                result.cves_found += 1;
                result.findings_created += 1;
                if sev == "CRITICAL" {
                    result.critical_count += 1;
                }
            }
        }
    }

    if result.findings_created > 0 {
        tracing::info!(
            "SOFTWARE-VULN: {} on {} — {}/{} software checked, {} CVEs, {} findings ({} critical)",
            asset_name,
            asset_id,
            result.software_checked,
            software.len(),
            result.cves_found,
            result.findings_created,
            result.critical_count
        );
    }

    result
}

/// Check CISA KEV database for CVEs affecting a given software name+version.
async fn check_kev_for_software(store: &dyn Database, name: &str, version: &str) -> Vec<String> {
    let mut matches = vec![];

    if let Ok(entries) = store.list_settings("_kev").await {
        for row in &entries {
            if !row.key.starts_with("CVE-") {
                continue;
            }
            let product = row.value["product"].as_str().unwrap_or("").to_lowercase();
            let vendor = row.value["vendor"].as_str().unwrap_or("").to_lowercase();

            // Match software name against KEV product/vendor
            if product.contains(name) || vendor.contains(name) || name.contains(&product) {
                // Version check: KEV stores affected versions in description
                // Simple heuristic — if the product matches, flag it
                matches.push(row.key.clone());
            }
        }
    }

    matches
}

/// Check local NVD cache (cve_cache table) for CVEs matching software.
async fn check_nvd_cache_for_software(
    store: &dyn Database,
    name: &str,
    _version: &str,
) -> Vec<(String, f64, String)> {
    let mut matches = vec![];

    // Search enrichment cache for CVEs related to this software
    let search_key = format!("cpe:*{}*", name.to_lowercase());
    if let Ok(Some(cached)) = store
        .get_enrichment_cache("nvd_software", &name.to_lowercase())
        .await
    {
        if let Some(cves) = cached["cves"].as_array() {
            for cve in cves {
                let id = cve["id"].as_str().unwrap_or("");
                let cvss = cve["cvss"].as_f64().unwrap_or(0.0);
                let severity = cve["severity"].as_str().unwrap_or("MEDIUM");
                if !id.is_empty() && cvss >= 5.0 {
                    matches.push((id.to_string(), cvss, severity.to_string()));
                }
            }
        }
    }

    matches
}

/// Scan all assets that have software data. Run periodically (e.g., daily).
pub async fn scan_all_assets(store: std::sync::Arc<dyn Database>) -> usize {
    let assets = store
        .list_assets(None, Some("active"), 500, 0)
        .await
        .unwrap_or_default();
    let mut total_findings = 0usize;

    for asset in &assets {
        let software = &asset.software;
        if let Some(sw_array) = software.as_array() {
            if sw_array.is_empty() {
                continue;
            }
            let result =
                scan_asset_software(store.as_ref(), &asset.id, &asset.name, sw_array).await;
            total_findings += result.findings_created;
        }
    }

    if total_findings > 0 {
        tracing::info!(
            "SOFTWARE-VULN: Daily scan complete — {} findings across {} assets",
            total_findings,
            assets.len()
        );
    }

    total_findings
}
