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
}
