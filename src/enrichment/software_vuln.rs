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

    // Dedup against this asset's existing vuln findings. Findings are grouped per
    // outdated component, so the key is software+version (not per-CVE).
    let existing_findings = store
        .list_findings(None, None, Some(asset_name), 1000, 0)
        .await
        .unwrap_or_default();
    let mut seen: std::collections::HashSet<String> = existing_findings
        .iter()
        .filter_map(|f| {
            let pkg = f.metadata.get("software")?.as_str()?;
            let ver = f
                .metadata
                .get("version")
                .and_then(|s| s.as_str())
                .unwrap_or("");
            Some(format!("{pkg}|{ver}"))
        })
        .collect();

    let ecosystem = ecosystem_for_platform(platform);
    let cpe_path = crate::enrichment::grype::uses_cpe(platform);

    // Build a CycloneDX SBOM and let Grype do the matching — distro-aware on Linux
    // (backport-aware, so a +debXuY patched package is correctly NOT flagged), CPE
    // on Windows, with CVSS / EPSS / CISA-KEV / fix enrichment per CVE. This
    // replaces the old name-substring + version-ignored matching (~73/75 FP).
    let sbom = crate::enrichment::grype::build_sbom(platform, software);
    // TMPDIR (set to the writable data volume in the image — the container's /tmp
    // is root-owned 0700). Create it so a fresh install doesn't fail the first
    // scan, and surface a write failure instead of silently producing no findings.
    let tmp_dir = std::env::temp_dir();
    let _ = std::fs::create_dir_all(&tmp_dir);
    let sbom_path = tmp_dir.join(format!("tc-sbom-{asset_id}.json"));
    if let Err(e) = std::fs::write(&sbom_path, sbom.to_string()) {
        tracing::warn!(
            "SOFTWARE-VULN: cannot write SBOM to {} ({e}) — scan skipped for {asset_name}",
            sbom_path.display()
        );
        return result;
    }
    let matches = crate::enrichment::grype::scan_sbom(&sbom_path.to_string_lossy());
    let _ = std::fs::remove_file(&sbom_path);

    // Filter to what an operator must act on, then group survivors by outdated
    // component (software+version): one stale Chrome with 21 CVEs becomes ONE
    // actionable finding ("update to X"), not 21 lines saying the same thing.
    let mut groups: std::collections::BTreeMap<
        (String, String),
        Vec<&crate::enrichment::grype::GrypeMatch>,
    > = std::collections::BTreeMap::new();
    for m in &matches {
        // Prioritise: actively exploited (CISA KEV) or high/critical. Medium/low/
        // negligible are real but kept out of the alert stream so we don't drown the SOC.
        let rank = severity_rank(&m.severity);
        if !(m.known_exploited || rank >= 3) {
            continue;
        }
        // CPE-matched platforms (Windows/other): require a fix version. NVD CPE
        // configs frequently have no upper version bound and match every release of a
        // product (a current Edge flagged for a 2015 Flash CVE, even tagged KEV) —
        // pure noise. A fix version means grype actually computed installed < fixed.
        // Distro (Linux) matching is precise, so not-yet-fixed vulns stay surfaced.
        if cpe_path && m.fixed_version.is_none() {
            continue;
        }
        groups
            .entry((m.package.clone(), m.version.clone()))
            .or_default()
            .push(m);
    }

    for ((package, version), ms) in &groups {
        if !seen.insert(format!("{package}|{version}")) {
            continue;
        }
        // Aggregate the group: highest severity drives the finding, KEV → CRITICAL.
        let any_kev = ms.iter().any(|m| m.known_exploited);
        let max_rank = ms.iter().map(|m| severity_rank(&m.severity)).max().unwrap_or(0);
        let severity = if any_kev || max_rank >= 4 {
            "CRITICAL"
        } else {
            "HIGH"
        };
        let crit_count = ms
            .iter()
            .filter(|m| m.known_exploited || severity_rank(&m.severity) >= 4)
            .count();
        let max_cvss = ms
            .iter()
            .filter_map(|m| m.cvss)
            .fold(None, |acc, x| Some(acc.map_or(x, |a: f64| a.max(x))));
        // The highest-CVSS match leads — it drives the recommended fix version.
        let lead = ms
            .iter()
            .max_by(|a, b| {
                a.cvss
                    .unwrap_or(0.0)
                    .partial_cmp(&b.cvss.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .unwrap();
        let cves: Vec<&str> = ms.iter().map(|m| m.cve_id.as_str()).collect();
        let n = cves.len();
        let kev_tag = if any_kev { " (CISA KEV: exploit actif)" } else { "" };
        let fix_hint = lead
            .fixed_version
            .as_deref()
            .map(|v| format!(", corriger en {v}"))
            .unwrap_or_default();

        let title = if n == 1 {
            format!("{package} {version} — {}{kev_tag}", cves[0])
        } else {
            let crit = if crit_count > 0 {
                format!(", dont {crit_count} critical")
            } else {
                String::new()
            };
            format!("{package} {version} — {n} CVE{crit}{kev_tag}")
        };
        let description = if n == 1 {
            format!(
                "Le logiciel {package} version {version} sur {asset_name} est affecté par {}{}{fix_hint}.",
                cves[0],
                max_cvss.map(|c| format!(" (CVSS {c:.1})")).unwrap_or_default()
            )
        } else {
            format!(
                "Le logiciel {package} version {version} sur {asset_name} est affecté par {n} vulnérabilités{}{fix_hint}. CVE : {}.",
                max_cvss.map(|c| format!(" (CVSS max {c:.1})")).unwrap_or_default(),
                cves.join(", ")
            )
        };

        let _ = store
            .insert_finding(&crate::db::threatclaw_store::NewFinding {
                skill_id: "software-vuln".into(),
                title,
                description: Some(description),
                severity: severity.into(),
                category: Some("software-vuln".into()),
                asset: Some(asset_name.to_string()),
                source: Some("Grype × osquery".into()),
                metadata: Some(serde_json::json!({
                    "cve": lead.cve_id,         // representative (highest CVSS), for back-compat
                    "cves": cves,
                    "cve_count": n,
                    "software": package,
                    "version": version,
                    "platform": platform,
                    "ecosystem": ecosystem,
                    "cvss": max_cvss,
                    "epss": lead.epss,
                    "exploited_in_wild": any_kev,
                    "fix_state": lead.fix_state,
                    "fixed_version": lead.fixed_version,
                    "data_source": lead.data_source,
                    "detection": "software-vuln-grype",
                    "mitre": ["T1190"],
                    "i18n": crate::enrichment::finding_i18n::i18n(
                        software_vuln_i18n_key(n, any_kev, crit_count > 0),
                        serde_json::json!({
                            "package": package,
                            "version": version,
                            "cve": lead.cve_id,
                            "n": n,
                            "crit": crit_count,
                        }),
                    ),
                })),
            })
            .await;
        result.cves_found += n;
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

/// Pick the precomposed i18n key for a grouped software-vuln finding title. The
/// French conditional fragments (KEV / "dont N critical") can't be passed as
/// params — each shape gets its own key so the catalog translates the whole title.
fn software_vuln_i18n_key(n: usize, any_kev: bool, has_crit: bool) -> &'static str {
    match (n > 1, has_crit, any_kev) {
        (false, _, false) => "finding.software_vuln.cve_single",
        (false, _, true) => "finding.software_vuln.cve_single_kev",
        (true, false, false) => "finding.software_vuln.cve_group",
        (true, false, true) => "finding.software_vuln.cve_group_kev",
        (true, true, false) => "finding.software_vuln.cve_group_crit",
        (true, true, true) => "finding.software_vuln.cve_group_crit_kev",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i18n_key_selection() {
        // args: (n, any_kev, has_crit)
        assert_eq!(software_vuln_i18n_key(1, false, false), "finding.software_vuln.cve_single");
        assert_eq!(software_vuln_i18n_key(1, true, false), "finding.software_vuln.cve_single_kev");
        assert_eq!(software_vuln_i18n_key(3, false, false), "finding.software_vuln.cve_group");
        assert_eq!(software_vuln_i18n_key(3, true, false), "finding.software_vuln.cve_group_kev");
        assert_eq!(software_vuln_i18n_key(3, false, true), "finding.software_vuln.cve_group_crit");
        assert_eq!(software_vuln_i18n_key(3, true, true), "finding.software_vuln.cve_group_crit_kev");
    }
}
