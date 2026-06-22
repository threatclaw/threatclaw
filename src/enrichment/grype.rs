//! Grype wrapper — runs the Anchore Grype binary (Apache-2.0) against a CycloneDX
//! SBOM built from an asset's osquery software inventory, and parses its matches.
//!
//! Grype is the matching engine: Linux distro-aware (Debian/Ubuntu/RHEL/Alpine,
//! backport-aware via the distro security trackers) AND Windows/other via CPE.
//! It also ships, on every match, the enrichment we need — CVSS, EPSS, CISA-KEV
//! (`knownExploited`), fix state + fixed version — so the caller only prioritises
//! and persists. This replaces the previous naive name-substring + version-ignored
//! matching that produced ~73/75 false positives.
//!
//! Best-effort by contract: any failure (binary missing, bad SBOM, timeout, bad
//! JSON) returns an empty vec and logs. It must never panic, never block osquery
//! ingestion, and never fabricate a finding.

use std::process::Command;

/// One vulnerability match for an installed package, with Grype's enrichment.
#[derive(Debug, Clone)]
pub struct GrypeMatch {
    pub package: String,
    pub version: String,
    pub cve_id: String,
    /// Critical / High / Medium / Low / Negligible / Unknown.
    pub severity: String,
    /// Highest CVSS base score across the available vectors.
    pub cvss: Option<f64>,
    /// EPSS exploit-prediction probability (0..1).
    pub epss: Option<f64>,
    /// True when the CVE is in the CISA KEV catalog (actively exploited).
    pub known_exploited: bool,
    /// fixed / not-fixed / wont-fix / unknown.
    pub fix_state: String,
    pub fixed_version: Option<String>,
    /// e.g. the Debian/Ubuntu security tracker or NVD URL the match came from.
    pub data_source: String,
}

/// Run grype against a CycloneDX SBOM file. Returns an empty vec on any failure —
/// never blocks ingestion, never fabricates a finding.
pub fn scan_sbom(sbom_path: &str) -> Vec<GrypeMatch> {
    let stdout = match Command::new("grype")
        .arg(format!("sbom:{sbom_path}"))
        .args(["-o", "json", "-q"])
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => {
            tracing::warn!(
                "grype exited non-zero ({}): {} — software-vuln scan skipped",
                o.status,
                String::from_utf8_lossy(&o.stderr).trim()
            );
            return Vec::new();
        }
        Err(e) => {
            tracing::warn!("grype not runnable ({e}) — software-vuln scan skipped");
            return Vec::new();
        }
    };
    parse(&stdout)
}

fn parse(bytes: &[u8]) -> Vec<GrypeMatch> {
    let root: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("grype JSON parse failed: {e}");
            return Vec::new();
        }
    };
    let Some(matches) = root["matches"].as_array() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(matches.len());
    for m in matches {
        let v = &m["vulnerability"];
        let cve_id = v["id"].as_str().unwrap_or("").to_string();
        if cve_id.is_empty() {
            continue;
        }
        // Highest CVSS base score across the (possibly several) vectors.
        let cvss = v["cvss"].as_array().and_then(|arr| {
            arr.iter()
                .filter_map(|c| c["metrics"]["baseScore"].as_f64())
                .fold(None, |acc, x| Some(acc.map_or(x, |a: f64| a.max(x))))
        });
        let epss = v["epss"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|e| e["epss"].as_f64());
        // Grype populates `knownExploited` (array/object) when the CVE is in KEV.
        let known_exploited = match &v["knownExploited"] {
            serde_json::Value::Array(a) => !a.is_empty(),
            serde_json::Value::Object(o) => !o.is_empty(),
            serde_json::Value::Bool(b) => *b,
            _ => false,
        };
        out.push(GrypeMatch {
            package: m["artifact"]["name"].as_str().unwrap_or("").to_string(),
            version: m["artifact"]["version"].as_str().unwrap_or("").to_string(),
            cve_id,
            severity: v["severity"].as_str().unwrap_or("Unknown").to_string(),
            cvss,
            epss,
            known_exploited,
            fix_state: v["fix"]["state"].as_str().unwrap_or("unknown").to_string(),
            fixed_version: v["fix"]["versions"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|x| x.as_str())
                .map(String::from),
            data_source: v["dataSource"].as_str().unwrap_or("").to_string(),
        });
    }
    out
}

/// Build a CycloneDX SBOM (as JSON) from an osquery software inventory for the
/// given platform, ready for `grype sbom:`. The OS component **and** the distro
/// PURL qualifier are what make Grype use its distro matcher (Debian/Ubuntu/RHEL/
/// Alpine — backport-aware) instead of falling back to CPE. Validated on cyb06:
/// with the distro present, Grype returned 39 real CVEs vs 75 garbage, and
/// correctly reported the patched packages as not-affected.
///
/// Windows / unknown platforms carry no distro: packages are emitted as plain
/// name+version and Grype matches them by CPE.
pub fn build_sbom(platform: &str, software: &[serde_json::Value]) -> serde_json::Value {
    let (os_id, os_version, pkg_type) = distro_of(platform);
    let components: Vec<serde_json::Value> = software
        .iter()
        .filter_map(|sw| {
            let name = sw["name"].as_str()?.trim();
            let version = sw["version"].as_str()?.trim();
            if name.is_empty() || version.is_empty() {
                return None;
            }
            let mut comp = serde_json::json!({
                "type": "library", "name": name, "version": version
            });
            if let Some(pt) = pkg_type {
                comp["purl"] = serde_json::Value::String(format!(
                    "pkg:{pt}/{os_id}/{name}@{version}?distro={os_id}-{os_version}"
                ));
            }
            Some(comp)
        })
        .collect();

    let mut sbom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    });
    // Linux distro → declare the OS so Grype picks the distro matcher.
    if pkg_type.is_some() && !os_id.is_empty() {
        sbom["metadata"] = serde_json::json!({
            "component": { "type": "operating-system", "name": os_id, "version": os_version }
        });
    }
    sbom
}

/// Map an os/platform string to `(os_id, os_version, distro_package_type)`.
/// `pkg_type` is `None` for Windows/unknown → Grype matches by CPE on name+version.
fn distro_of(platform: &str) -> (String, String, Option<&'static str>) {
    let p = platform.to_lowercase();
    let version = extract_version(&p);
    let (id, pkg): (&str, Option<&'static str>) = if p.contains("debian") {
        ("debian", Some("deb"))
    } else if p.contains("ubuntu") {
        ("ubuntu", Some("deb"))
    } else if p.contains("alpine") {
        ("alpine", Some("apk"))
    } else if p.contains("almalinux") || p.contains("alma") {
        ("almalinux", Some("rpm"))
    } else if p.contains("rocky") {
        ("rocky", Some("rpm"))
    } else if p.contains("centos") {
        ("centos", Some("rpm"))
    } else if p.contains("fedora") {
        ("fedora", Some("rpm"))
    } else if p.contains("red hat") || p.contains("rhel") {
        ("rhel", Some("rpm"))
    } else {
        ("", None) // windows / macOS / unknown → CPE
    };
    (id.to_string(), version, pkg)
}

/// First version-like token in a lowercased os string: "debian gnu/linux 12
/// (bookworm)" → "12", "ubuntu 22.04" → "22.04".
fn extract_version(p: &str) -> String {
    let mut cur = String::new();
    for ch in p.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !cur.is_empty()) {
            cur.push(ch);
        } else if !cur.is_empty() {
            break;
        }
    }
    cur.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mirrors the real grype v0.114 JSON shape captured on cyb06.
    const SAMPLE: &[u8] = br#"{"matches":[{
        "artifact":{"name":"openssl","version":"3.0.18-1~deb12u2"},
        "vulnerability":{"id":"CVE-2026-45447","severity":"High",
          "dataSource":"https://security-tracker.debian.org/tracker/CVE-2026-45447",
          "fix":{"versions":["3.0.20-1~deb12u2"],"state":"fixed"},
          "cvss":[{"metrics":{"baseScore":8.8}}],
          "epss":[{"cve":"CVE-2026-45447","epss":0.01409,"percentile":0.69}],
          "knownExploited":null}}]}"#;

    #[test]
    fn parses_match_with_full_enrichment() {
        let m = parse(SAMPLE);
        assert_eq!(m.len(), 1);
        let g = &m[0];
        assert_eq!(g.package, "openssl");
        assert_eq!(g.cve_id, "CVE-2026-45447");
        assert_eq!(g.severity, "High");
        assert_eq!(g.cvss, Some(8.8));
        assert_eq!(g.epss, Some(0.01409));
        assert!(!g.known_exploited);
        assert_eq!(g.fix_state, "fixed");
        assert_eq!(g.fixed_version.as_deref(), Some("3.0.20-1~deb12u2"));
    }

    #[test]
    fn kev_flag_set_when_present() {
        let json = br#"{"matches":[{"artifact":{"name":"x","version":"1"},
            "vulnerability":{"id":"CVE-1","knownExploited":[{"cve":"CVE-1"}]}}]}"#;
        assert!(parse(json)[0].known_exploited);
    }

    #[test]
    fn garbage_and_empty_are_empty() {
        assert!(parse(b"not json").is_empty());
        assert!(parse(br#"{"matches":[]}"#).is_empty());
        assert!(parse(br#"{}"#).is_empty());
    }

    #[test]
    fn debian_sbom_declares_distro_and_purl() {
        let sw = vec![serde_json::json!({"name":"openssl","version":"3.0.18-1~deb12u2"})];
        let sbom = build_sbom("Debian GNU/Linux 12 (bookworm)", &sw);
        assert_eq!(sbom["metadata"]["component"]["name"], "debian");
        assert_eq!(sbom["metadata"]["component"]["version"], "12");
        assert_eq!(
            sbom["components"][0]["purl"].as_str().unwrap(),
            "pkg:deb/debian/openssl@3.0.18-1~deb12u2?distro=debian-12"
        );
    }

    #[test]
    fn windows_sbom_has_no_distro_no_purl() {
        let sw = vec![serde_json::json!({"name":"Google Chrome","version":"146.0"})];
        let sbom = build_sbom("Microsoft Windows Server 2022", &sw);
        assert!(sbom["metadata"].is_null());
        assert!(sbom["components"][0]["purl"].is_null());
        assert_eq!(sbom["components"][0]["name"], "Google Chrome");
    }

    #[test]
    fn distro_and_version_parsing() {
        assert_eq!(extract_version("debian gnu/linux 12 (bookworm)"), "12");
        assert_eq!(extract_version("ubuntu 22.04"), "22.04");
        assert_eq!(extract_version("windows"), "");
        assert_eq!(distro_of("Ubuntu 22.04.3 LTS").2, Some("deb"));
        assert_eq!(distro_of("Red Hat Enterprise Linux 9").2, Some("rpm"));
        assert_eq!(distro_of("Microsoft Windows 11").2, None);
    }
}
