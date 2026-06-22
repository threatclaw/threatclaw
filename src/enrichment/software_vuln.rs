// See ADR-044: Auto-CVE correlation for software inventory.
//
// When the agent (osquery) reports an asset's installed software, we build a
// CycloneDX SBOM and let Grype match it (src/enrichment/grype.rs): distro-aware
// on Linux (backport-aware) and CPE on Windows, with CVSS/EPSS/CISA-KEV/fix
// enrichment per CVE. Findings surface only what an operator must act on (KEV or
// high/critical). Replaces the old naive name-substring + version-ignored matcher
// that produced ~73/75 false positives.

use crate::db::Database;

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
    platform: &str,
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

    result.software_checked = software.len();

    // Dedup against this asset's existing CVE findings. A CVE can legitimately
    // affect several packages, so the key is cve+package (not cve alone).
    let existing_findings = store
        .list_findings(None, None, Some(asset_name), 1000, 0)
        .await
        .unwrap_or_default();
    let mut seen: std::collections::HashSet<String> = existing_findings
        .iter()
        .filter_map(|f| {
            let cve = f.metadata.get("cve")?.as_str()?;
            let pkg = f
                .metadata
                .get("software")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            Some(format!("{cve}|{pkg}"))
        })
        .collect();

    let ecosystem = ecosystem_for_platform(platform);

    // Build a CycloneDX SBOM and let Grype do the matching — distro-aware on Linux
    // (backport-aware, so a +debXuY patched package is correctly NOT flagged), CPE
    // on Windows, with CVSS / EPSS / CISA-KEV / fix enrichment per CVE. This
    // replaces the old name-substring + version-ignored matching (~73/75 FP).
    let sbom = crate::enrichment::grype::build_sbom(platform, software);
    let sbom_path = std::env::temp_dir().join(format!("tc-sbom-{asset_id}.json"));
    if std::fs::write(&sbom_path, sbom.to_string()).is_err() {
        return result;
    }
    let matches = crate::enrichment::grype::scan_sbom(&sbom_path.to_string_lossy());
    let _ = std::fs::remove_file(&sbom_path);

    for m in &matches {
        // Prioritise: surface what an operator must act on — actively exploited
        // (CISA KEV) or high/critical severity. Medium/low/negligible and
        // won't-fix are real but kept out of the alert stream so we don't drown
        // the SOC (exactly the noise the old scanner produced).
        let rank = severity_rank(&m.severity);
        if !(m.known_exploited || rank >= 3) {
            continue;
        }
        if !seen.insert(format!("{}|{}", m.cve_id, m.package)) {
            continue;
        }

        // KEV is urgent regardless of base severity.
        let severity = if m.known_exploited || rank >= 4 {
            "CRITICAL"
        } else {
            "HIGH"
        };
        let kev_tag = if m.known_exploited {
            " (CISA KEV: exploit actif)"
        } else {
            ""
        };
        let fix_hint = m
            .fixed_version
            .as_deref()
            .map(|v| format!(", corrigé en {v}"))
            .unwrap_or_default();

        let _ = store
            .insert_finding(&crate::db::threatclaw_store::NewFinding {
                skill_id: "software-vuln".into(),
                title: format!("{} {} — {}{}", m.package, m.version, m.cve_id, kev_tag),
                description: Some(format!(
                    "Le logiciel {} version {} sur {} est affecté par {}{}{}.",
                    m.package,
                    m.version,
                    asset_name,
                    m.cve_id,
                    m.cvss.map(|c| format!(" (CVSS {c:.1})")).unwrap_or_default(),
                    fix_hint
                )),
                severity: severity.into(),
                category: Some("software-vuln".into()),
                asset: Some(asset_name.to_string()),
                source: Some("Grype × osquery".into()),
                metadata: Some(serde_json::json!({
                    "cve": m.cve_id,
                    "software": m.package,
                    "version": m.version,
                    "platform": platform,
                    "ecosystem": ecosystem,
                    "cvss": m.cvss,
                    "epss": m.epss,
                    "exploited_in_wild": m.known_exploited,
                    "fix_state": m.fix_state,
                    "fixed_version": m.fixed_version,
                    "data_source": m.data_source,
                    "detection": "software-vuln-grype",
                    "mitre": ["T1190"]
                })),
            })
            .await;
        result.cves_found += 1;
        result.findings_created += 1;
        if severity == "CRITICAL" {
            result.critical_count += 1;
        }
    }

    if result.findings_created > 0 {
        tracing::info!(
            "SOFTWARE-VULN: {} on {} — {} packages, {} grype matches, {} surfaced ({} critical)",
            asset_name,
            asset_id,
            software.len(),
            matches.len(),
            result.findings_created,
            result.critical_count
        );
    }

    result
}

/// Rank a Grype severity string for prioritisation. Negligible/Unknown = 0.
fn severity_rank(sev: &str) -> u8 {
    match sev.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}


/// Map an OS string (osquery `platform` or `asset.os`) to a matching ecosystem
/// for the Phase 2 distro-aware matcher. Linux distros map to their OSV ecosystem
/// (Debian/Ubuntu/Red Hat/Alpine — backport-aware version comparison); Windows
/// maps to CPE-based matching. Empty when unknown so the matcher can fall back to
/// CPE rather than guess.
fn ecosystem_for_platform(platform: &str) -> &'static str {
    let p = platform.to_lowercase();
    if p.contains("debian") {
        "Debian"
    } else if p.contains("ubuntu") {
        "Ubuntu"
    } else if p.contains("red hat")
        || p.contains("rhel")
        || p.contains("centos")
        || p.contains("rocky")
        || p.contains("almalinux")
        || p.contains("fedora")
    {
        "Red Hat"
    } else if p.contains("alpine") {
        "Alpine"
    } else if p.contains("windows") {
        "Windows"
    } else {
        ""
    }
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
            let result = scan_asset_software(
                store.as_ref(),
                &asset.id,
                &asset.name,
                asset.os.as_deref().unwrap_or(""),
                sw_array,
            )
            .await;
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
