// See ADR-044: Auto-CVE correlation for software inventory.
//
// When the agent (osquery) reports an asset's installed software, we build a
// CycloneDX SBOM and let Grype match it (src/enrichment/grype.rs): distro-aware
// on Linux (backport-aware) and CPE on Windows, with CVSS/EPSS/CISA-KEV/fix
// enrichment per CVE. Findings surface only what an operator must act on (KEV or
// high/critical). Replaces the old naive name-substring + version-ignored matcher
// that produced ~73/75 false positives.

use crate::db::Database;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

pub struct VulnScanResult {
    pub software_checked: usize,
    pub cves_found: usize,
    pub findings_created: usize,
    pub critical_count: usize,
}

// ── Targeted re-scan queue (scan-on-enroll / scan-on-change) ──────────────
//
// The daily scan_all_assets covers everything, but an asset onboarded — or whose
// software inventory changes — between two daily runs would otherwise wait up to
// 24h for its CVEs. Ingestion (osquery webhook) holds a borrowed `&dyn Database`
// and must not block on a ~2.5s Grype run, so it can't scan inline. Instead it
// drops the asset id here; the intelligence loop (which owns an `Arc<dyn Database>`)
// drains the queue once per cycle and scans the few assets that actually changed.
//
// In-memory on purpose: a restart runs a full scan_all_assets at boot anyway, so
// the queue only needs to bridge steady-state changes between daily scans.

/// Max assets scanned per drain. Caps the cost of a fleet-wide event (e.g. 10k
/// hosts re-reporting their inventory at once) so one cycle can't become a
/// multi-minute Grype storm — the overflow stays queued for the next cycle.
const MAX_RESCAN_PER_CYCLE: usize = 25;

fn rescan_queue() -> &'static Mutex<HashSet<String>> {
    static Q: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    Q.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Queue an asset for a near-term vulnerability re-scan. Called from osquery
/// ingestion when an inventory is first seen or changes. Idempotent (a HashSet),
/// so repeated marks before the next drain collapse to a single scan.
pub fn mark_for_rescan(asset_id: &str) {
    if let Ok(mut q) = rescan_queue().lock() {
        q.insert(asset_id.to_string());
    }
}

/// Number of assets currently waiting for a re-scan (observability / status).
pub fn rescan_queue_len() -> usize {
    rescan_queue().lock().map(|q| q.len()).unwrap_or(0)
}

/// Drain up to `MAX_RESCAN_PER_CYCLE` queued assets and scan each. Returns the
/// number of new findings created. Called once per intelligence cycle so a
/// freshly-onboarded or just-changed asset surfaces its CVEs in minutes instead
/// of waiting for the daily scan.
pub async fn drain_rescan_queue(store: Arc<dyn Database>) -> usize {
    // Take a bounded batch under the lock, then release it before any await —
    // a std Mutex guard must never be held across an await point.
    let batch: Vec<String> = {
        let mut q = match rescan_queue().lock() {
            Ok(q) => q,
            Err(_) => return 0,
        };
        if q.is_empty() {
            return 0;
        }
        let take: Vec<String> = q.iter().take(MAX_RESCAN_PER_CYCLE).cloned().collect();
        for id in &take {
            q.remove(id);
        }
        take
    };

    let remaining = rescan_queue_len();
    tracing::info!(
        "SOFTWARE-VULN: rescan queue — scanning {} asset(s){}",
        batch.len(),
        if remaining > 0 {
            format!(", {remaining} still queued for next cycle")
        } else {
            String::new()
        }
    );

    let mut total = 0usize;
    for asset_id in &batch {
        if let Ok(Some(asset)) = store.get_asset(asset_id).await {
            if let Some(sw) = asset.software.as_array() {
                if sw.is_empty() {
                    continue;
                }
                let r = scan_asset_software(
                    store.as_ref(),
                    &asset.id,
                    &asset.name,
                    asset.os.as_deref().unwrap_or(""),
                    sw,
                )
                .await;
                total += r.findings_created;
            }
        }
    }
    total
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
        let max_rank = ms
            .iter()
            .map(|m| severity_rank(&m.severity))
            .max()
            .unwrap_or(0);
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
        let kev_tag = if any_kev {
            " (CISA KEV: exploit actif)"
        } else {
            ""
        };
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
                max_cvss
                    .map(|c| format!(" (CVSS {c:.1})"))
                    .unwrap_or_default()
            )
        } else {
            format!(
                "Le logiciel {package} version {version} sur {asset_name} est affecté par {n} vulnérabilités{}{fix_hint}. CVE : {}.",
                max_cvss
                    .map(|c| format!(" (CVSS max {c:.1})"))
                    .unwrap_or_default(),
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

    // ── Per-asset exposure score (Grype × KEV × EPSS × criticality × exposure) ──
    // Roll this asset's actionable vulnerabilities up to one prioritised 0-100
    // score that drives the asset detail + the "Actions prioritaires" view and,
    // when notable, feeds the RBA so it escalates to an incident. Computed from
    // `groups` (the full current actionable posture of this scan), not just the
    // newly-created findings.
    if !groups.is_empty() {
        let mut asset_max_cvss = 0.0_f64;
        let mut asset_max_epss = 0.0_f64;
        let mut asset_any_kev = false;
        // Most actionable group drives the remediation shown: KEV first, then CVSS.
        let mut top: Option<(&crate::enrichment::grype::GrypeMatch, &str)> = None;
        for ((package, _version), ms) in &groups {
            let any_kev = ms.iter().any(|m| m.known_exploited);
            asset_any_kev |= any_kev;
            asset_max_cvss = asset_max_cvss.max(ms.iter().filter_map(|m| m.cvss).fold(0.0, f64::max));
            asset_max_epss = asset_max_epss.max(ms.iter().filter_map(|m| m.epss).fold(0.0, f64::max));
            let lead = ms
                .iter()
                .max_by(|a, b| {
                    a.cvss
                        .unwrap_or(0.0)
                        .partial_cmp(&b.cvss.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .unwrap();
            let better = match &top {
                None => true,
                Some((t, _)) => {
                    (any_kev && !t.known_exploited)
                        || (any_kev == t.known_exploited
                            && lead.cvss.unwrap_or(0.0) > t.cvss.unwrap_or(0.0))
                }
            };
            if better {
                top = Some((lead, package.as_str()));
            }
        }

        let asset = store.get_asset(asset_id).await.ok().flatten();
        let criticality = asset
            .as_ref()
            .map(|a| a.criticality.clone())
            .unwrap_or_else(|| "medium".to_string());
        let exposed = asset.as_ref().map(asset_is_exposed).unwrap_or(false);

        let input = crate::enrichment::exposure_score::ExposureInput {
            max_cvss: asset_max_cvss,
            in_kev: asset_any_kev,
            epss_max: asset_max_epss,
            criticality,
            exposed,
        };
        let res = crate::enrichment::exposure_score::compute_exposure(&input);
        let (top_cve, top_fix, top_software) = match top {
            Some((m, pkg)) => (
                Some(m.cve_id.clone()),
                m.fixed_version.clone(),
                Some(pkg.to_string()),
            ),
            None => (None, None, None),
        };

        let _ = store
            .set_asset_exposure(&crate::db::threatclaw_store::AssetExposure {
                asset_id: asset_id.to_string(),
                score: res.score as i16,
                severity: res.severity.to_string(),
                breakdown: res.breakdown.clone(),
                max_cvss: (asset_max_cvss > 0.0).then_some(asset_max_cvss),
                in_kev: asset_any_kev,
                epss_max: (asset_max_epss > 0.0).then_some(asset_max_epss),
                exposed,
                top_cve,
                top_fix,
                top_software,
                computed_at: String::new(), // set by the DB (NOW())
            })
            .await;

        // Notable exposure → push into the RBA pipeline (→ incident the RSSI acts on).
        if crate::enrichment::exposure_score::is_notable(&input, &res) {
            let _ = store
                .insert_risk_event(&crate::db::threatclaw_store::NewRiskEvent {
                    risk_object: asset_id.to_string(),
                    object_type: "asset".to_string(),
                    score: res.score as i32,
                    source_rule: "software-vuln-exposure".to_string(),
                    mitre_tactic: None,
                    mitre_technique: Some("T1190".to_string()),
                    log_id: None,
                    message: Some(format!(
                        "Exposition {} ({}/100) : {}",
                        res.severity,
                        res.score,
                        res.breakdown.join(", ")
                    )),
                })
                .await;
        }
    }

    result
}

/// An asset is internet-exposed if it carries the `public_ip` system tag (V98)
/// or any of its addresses is a public (non-RFC1918/loopback) IP.
fn asset_is_exposed(asset: &crate::db::threatclaw_store::AssetRecord) -> bool {
    asset.tags.iter().any(|t| t.eq_ignore_ascii_case("public_ip"))
        || asset.ip_addresses.iter().any(|ip| is_public_ip(ip))
}

/// A routable public IP (not RFC1918 / loopback / link-local / unspecified).
fn is_public_ip(ip: &str) -> bool {
    match ip.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        Ok(std::net::IpAddr::V6(v6)) => !(v6.is_loopback() || v6.is_unspecified()),
        Err(_) => false,
    }
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
        assert_eq!(
            software_vuln_i18n_key(1, false, false),
            "finding.software_vuln.cve_single"
        );
        assert_eq!(
            software_vuln_i18n_key(1, true, false),
            "finding.software_vuln.cve_single_kev"
        );
        assert_eq!(
            software_vuln_i18n_key(3, false, false),
            "finding.software_vuln.cve_group"
        );
        assert_eq!(
            software_vuln_i18n_key(3, true, false),
            "finding.software_vuln.cve_group_kev"
        );
        assert_eq!(
            software_vuln_i18n_key(3, false, true),
            "finding.software_vuln.cve_group_crit"
        );
        assert_eq!(
            software_vuln_i18n_key(3, true, true),
            "finding.software_vuln.cve_group_crit_kev"
        );
    }

    #[test]
    fn rescan_queue_dedups_marks() {
        // Unique id so this test doesn't race other users of the global queue.
        let id = "test-asset-rescan-dedup-9z";
        let before = rescan_queue_len();
        mark_for_rescan(id);
        mark_for_rescan(id); // idempotent — same id collapses to one entry
        assert!(
            rescan_queue_len() >= before + 1,
            "marking should enqueue the asset"
        );
        // A second distinct id grows the queue by exactly one more.
        let n = rescan_queue_len();
        mark_for_rescan("test-asset-rescan-dedup-9z-2");
        assert_eq!(rescan_queue_len(), n + 1);
    }

    #[test]
    fn is_public_ip_classifies_routable_addresses() {
        assert!(is_public_ip("8.8.8.8"));
        assert!(is_public_ip("149.71.41.85"));
        assert!(!is_public_ip("192.168.1.10"));
        assert!(!is_public_ip("10.0.0.5"));
        assert!(!is_public_ip("172.16.0.1"));
        assert!(!is_public_ip("127.0.0.1"));
        assert!(!is_public_ip("169.254.1.1"));
        assert!(!is_public_ip("not-an-ip"));
        assert!(!is_public_ip(""));
    }
}
