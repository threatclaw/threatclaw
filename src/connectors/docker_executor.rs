//! Docker Skill Executor — runs any security tool in an ephemeral container.
//!
//! Generic executor that:
//! 1. Pulls the Docker image (if not cached)
//! 2. Runs the command with resource limits
//! 3. Captures stdout (JSON or text)
//! 4. Parses results into findings
//! 5. Injects findings into ThreatClaw DB
//!
//! Used by all "tool" type skills (semgrep, checkov, trivy, etc.)

use crate::db::Database;
use crate::db::threatclaw_store::{NewFinding, ThreatClawStore};
use serde::{Deserialize, Serialize};
use std::process::Stdio;
use tokio::process::Command;

/// Configuration for a Docker-based skill execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSkillConfig {
    /// Docker image (e.g., "semgrep/semgrep:latest")
    pub image: String,
    /// Command + args (e.g., ["semgrep", "scan", "--config", "auto", "--json", "."])
    pub command: Vec<String>,
    /// Working directory to mount into the container (optional)
    pub mount_path: Option<String>,
    /// Container mount point for the working directory
    #[serde(default = "default_mount_target")]
    pub mount_target: String,
    /// Network mode ("none", "host", "bridge")
    #[serde(default = "default_network")]
    pub network: String,
    /// Memory limit (e.g., "256m", "1g")
    #[serde(default = "default_memory")]
    pub memory_limit: String,
    /// Timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Skill ID (for findings attribution)
    pub skill_id: String,
    /// Skill name (for display)
    pub skill_name: String,
}

fn default_mount_target() -> String { "/workspace".into() }
fn default_network() -> String { "none".into() }
fn default_memory() -> String { "256m".into() }
fn default_timeout() -> u64 { 300 }

/// Result of a Docker skill execution.
#[derive(Debug, Clone, Serialize)]
pub struct DockerSkillResult {
    pub skill_id: String,
    pub success: bool,
    pub exit_code: i32,
    pub stdout_lines: usize,
    pub findings_created: usize,
    pub duration_secs: u64,
    pub error: Option<String>,
}

/// Run a security tool in Docker and parse findings.
pub async fn execute_skill(
    store: &dyn Database,
    config: &DockerSkillConfig,
    finding_parser: impl Fn(&str) -> Vec<ParsedFinding>,
) -> DockerSkillResult {
    let start = std::time::Instant::now();
    let mut result = DockerSkillResult {
        skill_id: config.skill_id.clone(),
        success: false, exit_code: -1, stdout_lines: 0,
        findings_created: 0, duration_secs: 0, error: None,
    };

    tracing::info!("DOCKER SKILL: Running {} ({})", config.skill_name, config.image);

    // Build Docker command
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm"]);
    cmd.args(["--network", &config.network]);
    cmd.args(["--memory", &config.memory_limit]);
    cmd.args(["--cpus", "1"]);

    // Mount working directory if specified
    if let Some(ref mount_path) = config.mount_path {
        cmd.args(["-v", &format!("{}:{}", mount_path, config.mount_target)]);
        cmd.args(["-w", &config.mount_target]);
    }

    cmd.arg(&config.image);
    cmd.args(&config.command);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Execute with timeout
    let output = match tokio::time::timeout(
        std::time::Duration::from_secs(config.timeout_seconds),
        cmd.output()
    ).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            result.error = Some(format!("Docker execution failed: {}. Is Docker running?", e));
            tracing::error!("DOCKER SKILL: {} failed: {}", config.skill_name, e);
            result.duration_secs = start.elapsed().as_secs();
            return result;
        }
        Err(_) => {
            result.error = Some(format!("Timeout after {}s", config.timeout_seconds));
            tracing::error!("DOCKER SKILL: {} timed out", config.skill_name);
            result.duration_secs = start.elapsed().as_secs();
            return result;
        }
    };

    result.exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    result.stdout_lines = stdout.lines().count();

    // Some tools return exit code 1 when findings are found (not an error)
    // e.g., semgrep returns 1 if findings, trivy returns 1 if vulns
    if result.exit_code > 1 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.error = Some(format!("Exit code {}: {}", result.exit_code, stderr.chars().take(500).collect::<String>()));
        tracing::warn!("DOCKER SKILL: {} exit code {}", config.skill_name, result.exit_code);
    }

    // Parse findings from stdout
    let parsed = finding_parser(&stdout);
    tracing::info!("DOCKER SKILL: {} produced {} findings", config.skill_name, parsed.len());

    // Insert findings into DB
    for finding in &parsed {
        let _ = store.insert_finding(&NewFinding {
            skill_id: config.skill_id.clone(),
            title: finding.title.clone(),
            description: Some(finding.description.clone()),
            severity: finding.severity.clone(),
            category: Some(finding.category.clone()),
            asset: finding.asset.clone(),
            source: Some(config.skill_name.clone()),
            metadata: Some(finding.metadata.clone()),
        }).await;
        result.findings_created += 1;
    }

    result.success = true;
    result.duration_secs = start.elapsed().as_secs();

    tracing::info!("DOCKER SKILL: {} complete — {} findings, {}s",
        config.skill_name, result.findings_created, result.duration_secs);

    result
}

/// A finding parsed from tool output.
#[derive(Debug, Clone)]
pub struct ParsedFinding {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub asset: Option<String>,
    pub metadata: serde_json::Value,
}

// ══════════════════════════════════════════════════════════
// PARSERS — one per tool, converts tool output to findings
// ══════════════════════════════════════════════════════════

/// Parse Semgrep JSON output into findings.
pub fn parse_semgrep(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(results) = json.get("results").and_then(|r| r.as_array()) {
        for r in results {
            let rule_id = r["check_id"].as_str().unwrap_or("unknown");
            let message = r["extra"]["message"].as_str().unwrap_or("");
            let severity = r["extra"]["severity"].as_str().unwrap_or("MEDIUM");
            let file = r["path"].as_str().unwrap_or("");
            let line = r["start"]["line"].as_i64().unwrap_or(0);

            findings.push(ParsedFinding {
                title: format!("{} — {}:{}", rule_id, file, line),
                description: message.to_string(),
                severity: normalize_severity(severity),
                category: "sast".into(),
                asset: Some(file.to_string()),
                metadata: serde_json::json!({
                    "rule_id": rule_id, "file": file, "line": line,
                    "tool": "semgrep",
                }),
            });
        }
    }
    findings
}

/// Parse Checkov JSON output into findings.
pub fn parse_checkov(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let failed = json.get("results").and_then(|r| r.get("failed_checks")).and_then(|f| f.as_array());
    if let Some(checks) = failed {
        for check in checks {
            let id = check["check_id"].as_str().unwrap_or("unknown");
            let name = check["check_result"]["name"].as_str()
                .or(check["name"].as_str())
                .unwrap_or(id);
            let file = check["file_path"].as_str().unwrap_or("");
            let resource = check["resource"].as_str().unwrap_or("");
            let severity = check["severity"].as_str().unwrap_or("MEDIUM");

            findings.push(ParsedFinding {
                title: format!("{} — {}", id, name),
                description: format!("Fichier: {} — Ressource: {}", file, resource),
                severity: normalize_severity(severity),
                category: "iac".into(),
                asset: Some(file.to_string()),
                metadata: serde_json::json!({
                    "check_id": id, "file": file, "resource": resource,
                    "tool": "checkov",
                }),
            });
        }
    }
    findings
}

/// Parse TruffleHog JSON output (one JSON object per line).
pub fn parse_trufflehog(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    for line in stdout.lines() {
        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let detector = json["DetectorName"].as_str().unwrap_or("unknown");
        let file = json["SourceMetadata"]["Data"]["Filesystem"]["file"].as_str()
            .or(json["SourceMetadata"]["Data"]["Git"]["file"].as_str())
            .unwrap_or("");
        let raw = json["Raw"].as_str().unwrap_or("").chars().take(20).collect::<String>();
        let verified = json["Verified"].as_bool().unwrap_or(false);

        findings.push(ParsedFinding {
            title: format!("Secret {} dans {}", detector, file),
            description: format!("Type: {} — Verifie: {} — Apercu: {}...", detector, verified, raw),
            severity: if verified { "CRITICAL".into() } else { "HIGH".into() },
            category: "secrets".into(),
            asset: Some(file.to_string()),
            metadata: serde_json::json!({
                "detector": detector, "file": file, "verified": verified,
                "tool": "trufflehog",
            }),
        });
    }
    findings
}

/// Parse Syft JSON (SPDX) output into findings (SBOM inventory, not vulns).
pub fn parse_syft(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(packages) = json.get("artifacts").and_then(|a| a.as_array()) {
        // SBOM is informational — create one summary finding
        findings.push(ParsedFinding {
            title: format!("SBOM — {} composants detectes", packages.len()),
            description: format!("{} packages/libraries identifies dans l'image", packages.len()),
            severity: "LOW".into(),
            category: "sbom".into(),
            asset: None,
            metadata: serde_json::json!({
                "package_count": packages.len(),
                "tool": "syft",
            }),
        });
    }
    findings
}

/// Parse Grype JSON output into findings.
pub fn parse_grype(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(matches) = json.get("matches").and_then(|m| m.as_array()) {
        for m in matches {
            let vuln_id = m["vulnerability"]["id"].as_str().unwrap_or("unknown");
            let severity = m["vulnerability"]["severity"].as_str().unwrap_or("MEDIUM");
            let pkg_name = m["artifact"]["name"].as_str().unwrap_or("");
            let pkg_version = m["artifact"]["version"].as_str().unwrap_or("");
            let fixed_in = m["vulnerability"]["fix"]["versions"].as_array()
                .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();

            findings.push(ParsedFinding {
                title: format!("{} — {} {}", vuln_id, pkg_name, pkg_version),
                description: format!("Package {} {} vulnerable. Fix: {}", pkg_name, pkg_version,
                    if fixed_in.is_empty() { "pas de fix disponible" } else { &fixed_in }),
                severity: normalize_severity(severity),
                category: "container-vuln".into(),
                asset: Some(format!("{}:{}", pkg_name, pkg_version)),
                metadata: serde_json::json!({
                    "cve": vuln_id, "package": pkg_name, "version": pkg_version,
                    "fixed_in": fixed_in, "tool": "grype",
                }),
            });
        }
    }
    findings
}

/// Parse ZAP JSON output into findings.
pub fn parse_zap(stdout: &str) -> Vec<ParsedFinding> {
    let mut findings = vec![];
    let json: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    // ZAP JSON report format: { "site": [{ "alerts": [...] }] }
    let sites = json.get("site").and_then(|s| s.as_array()).cloned().unwrap_or_default();
    for site in &sites {
        let site_name = site["@name"].as_str().unwrap_or("");
        let alerts = site.get("alerts").and_then(|a| a.as_array()).cloned().unwrap_or_default();
        for alert in &alerts {
            let name = alert["name"].as_str().unwrap_or("unknown");
            let risk = alert["riskdesc"].as_str().unwrap_or("Medium");
            let desc = alert["desc"].as_str().unwrap_or("");
            let solution = alert["solution"].as_str().unwrap_or("");
            let count = alert["count"].as_str().unwrap_or("1");

            findings.push(ParsedFinding {
                title: format!("{} — {}", name, site_name),
                description: format!("{}\nSolution: {}\nInstances: {}", desc, solution, count),
                severity: normalize_zap_risk(risk),
                category: "dast".into(),
                asset: Some(site_name.to_string()),
                metadata: serde_json::json!({
                    "alert": name, "site": site_name, "instances": count,
                    "tool": "zap",
                }),
            });
        }
    }
    findings
}

fn normalize_severity(s: &str) -> String {
    match s.to_uppercase().as_str() {
        "CRITICAL" | "ERROR" => "CRITICAL".into(),
        "HIGH" | "WARNING" => "HIGH".into(),
        "MEDIUM" | "INFO" => "MEDIUM".into(),
        "LOW" | "NOTE" => "LOW".into(),
        _ => "MEDIUM".into(),
    }
}

fn normalize_zap_risk(risk: &str) -> String {
    let lower = risk.to_lowercase();
    if lower.contains("high") { "HIGH".into() }
    else if lower.contains("medium") { "MEDIUM".into() }
    else if lower.contains("low") { "LOW".into() }
    else if lower.contains("info") { "LOW".into() }
    else { "MEDIUM".into() }
}

/// Pre-built configurations for common tools.
pub fn semgrep_config(target_path: &str) -> DockerSkillConfig {
    DockerSkillConfig {
        image: "semgrep/semgrep:latest".into(),
        command: vec!["semgrep".into(), "scan".into(), "--config".into(), "auto".into(), "--json".into(), ".".into()],
        mount_path: Some(target_path.into()),
        mount_target: "/workspace".into(),
        network: "none".into(),
        memory_limit: "1g".into(),
        timeout_seconds: 600,
        skill_id: "skill-semgrep".into(),
        skill_name: "Semgrep SAST".into(),
    }
}

pub fn checkov_config(target_path: &str) -> DockerSkillConfig {
    DockerSkillConfig {
        image: "bridgecrew/checkov:latest".into(),
        command: vec!["checkov".into(), "-d".into(), ".".into(), "-o".into(), "json".into()],
        mount_path: Some(target_path.into()),
        mount_target: "/workspace".into(),
        network: "none".into(),
        memory_limit: "512m".into(),
        timeout_seconds: 300,
        skill_id: "skill-checkov".into(),
        skill_name: "Checkov IaC".into(),
    }
}

pub fn trufflehog_config(target_path: &str) -> DockerSkillConfig {
    DockerSkillConfig {
        image: "trufflesecurity/trufflehog:latest".into(),
        command: vec!["trufflehog".into(), "filesystem".into(), "--json".into(), ".".into()],
        mount_path: Some(target_path.into()),
        mount_target: "/workspace".into(),
        network: "none".into(),
        memory_limit: "512m".into(),
        timeout_seconds: 300,
        skill_id: "skill-trufflehog".into(),
        skill_name: "TruffleHog Secrets".into(),
    }
}

pub fn grype_config(image: &str) -> DockerSkillConfig {
    DockerSkillConfig {
        image: "anchore/grype:latest".into(),
        command: vec!["grype".into(), image.into(), "-o".into(), "json".into()],
        mount_path: None,
        mount_target: "/workspace".into(),
        network: "bridge".into(), // Needs to pull image
        memory_limit: "512m".into(),
        timeout_seconds: 300,
        skill_id: "skill-grype".into(),
        skill_name: "Grype Container CVE".into(),
    }
}

pub fn syft_config(image: &str) -> DockerSkillConfig {
    DockerSkillConfig {
        image: "anchore/syft:latest".into(),
        command: vec!["syft".into(), image.into(), "-o".into(), "json".into()],
        mount_path: None,
        mount_target: "/workspace".into(),
        network: "bridge".into(),
        memory_limit: "512m".into(),
        timeout_seconds: 300,
        skill_id: "skill-syft".into(),
        skill_name: "Syft SBOM".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semgrep_empty() {
        assert_eq!(parse_semgrep("not json").len(), 0);
        assert_eq!(parse_semgrep(r#"{"results":[]}"#).len(), 0);
    }

    #[test]
    fn test_parse_semgrep_finding() {
        let json = r#"{"results":[{
            "check_id":"rules.python.sql-injection",
            "path":"app.py","start":{"line":42},
            "extra":{"message":"SQL injection via string concatenation","severity":"ERROR"}
        }]}"#;
        let findings = parse_semgrep(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "CRITICAL");
        assert!(findings[0].title.contains("sql-injection"));
    }

    #[test]
    fn test_parse_trufflehog() {
        let line = r#"{"DetectorName":"AWS","Raw":"AKIA1234567890ABCDEF","Verified":true,"SourceMetadata":{"Data":{"Filesystem":{"file":"config.py"}}}}"#;
        let findings = parse_trufflehog(line);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "CRITICAL"); // Verified = CRITICAL
        assert!(findings[0].title.contains("AWS"));
    }

    #[test]
    fn test_parse_grype() {
        let json = r#"{"matches":[{
            "vulnerability":{"id":"CVE-2024-1234","severity":"Critical","fix":{"versions":["1.2.3"]}},
            "artifact":{"name":"openssl","version":"1.1.1"}
        }]}"#;
        let findings = parse_grype(json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "CRITICAL");
        assert!(findings[0].title.contains("CVE-2024-1234"));
    }

    #[test]
    fn test_normalize_severity() {
        assert_eq!(normalize_severity("ERROR"), "CRITICAL");
        assert_eq!(normalize_severity("WARNING"), "HIGH");
        assert_eq!(normalize_severity("high"), "HIGH");
        assert_eq!(normalize_severity("info"), "MEDIUM");
    }
}
