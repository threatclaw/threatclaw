//! Nuclei scanner — CVE and vulnerability detection.
//!
//! Supports 3 modes:
//! - Docker: `docker exec <container> nuclei -target <target> -json`
//! - LocalBinary: `/usr/local/bin/nuclei -target <target> -json`
//! - RemoteApi: not supported by Nuclei (no REST API)

use async_trait::async_trait;
use std::process::Command;
use std::time::Instant;

use super::backend::*;

pub struct NucleiScanner {
    config: ScannerConfig,
}

impl NucleiScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self { config }
    }

    pub fn docker(container: &str) -> Self {
        Self::new(ScannerConfig {
            mode: ScannerMode::Docker,
            container: Some(container.to_string()),
            ..Default::default()
        })
    }

    pub fn local(binary_path: &str) -> Self {
        Self::new(ScannerConfig {
            mode: ScannerMode::LocalBinary,
            binary_path: Some(binary_path.to_string()),
            ..Default::default()
        })
    }

    fn parse_nuclei_json(output: &str) -> Vec<ScanFinding> {
        output
            .lines()
            .filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                let template_id = v["template-id"].as_str().unwrap_or("unknown");
                let name = v["info"]["name"].as_str().unwrap_or(template_id);
                let severity = v["info"]["severity"].as_str().unwrap_or("info").to_lowercase();
                let matched_at = v["matched-at"].as_str().unwrap_or("");
                let description = v["info"]["description"].as_str().map(|s| s.to_string());
                let tags = v["info"]["tags"].clone();
                let reference = v["info"]["reference"].clone();

                Some(ScanFinding {
                    title: name.to_string(),
                    severity,
                    asset: matched_at.to_string(),
                    source: "nuclei".to_string(),
                    description,
                    metadata: serde_json::json!({
                        "template": template_id,
                        "tags": tags,
                        "reference": reference,
                    }),
                })
            })
            .collect()
    }
}

#[async_trait]
impl ScannerBackend for NucleiScanner {
    fn name(&self) -> &str {
        "nuclei"
    }

    async fn health_check(&self) -> Result<String, String> {
        let output = match &self.config.mode {
            ScannerMode::Docker => {
                let container = self.config.container.as_deref().unwrap_or("docker-nuclei-1");
                Command::new("docker")
                    .args(["exec", container, "nuclei", "--version"])
                    .output()
                    .map_err(|e| format!("Docker exec failed: {e}"))?
            }
            ScannerMode::LocalBinary => {
                let path = self.config.binary_path.as_deref().unwrap_or("nuclei");
                Command::new(path)
                    .arg("--version")
                    .output()
                    .map_err(|e| format!("Binary not found: {e}"))?
            }
            ScannerMode::RemoteApi => {
                return Err("Nuclei does not support remote API mode".to_string());
            }
        };

        if output.status.success() {
            let version = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Ok(version)
        } else {
            Err("Nuclei not responding".to_string())
        }
    }

    async fn scan(&self, target: &str, options: &serde_json::Value) -> Result<ScanResult, String> {
        let start = Instant::now();
        let severity_filter = options["severity"].as_str().unwrap_or("critical,high,medium");

        let output = match &self.config.mode {
            ScannerMode::Docker => {
                let container = self.config.container.as_deref().unwrap_or("docker-nuclei-1");
                Command::new("docker")
                    .args([
                        "exec", container, "nuclei",
                        "-target", target,
                        "-severity", severity_filter,
                        "-json", "-silent",
                        "-rate-limit", "50",
                        "-timeout", "5",
                        "-retries", "1",
                    ])
                    .output()
                    .map_err(|e| format!("Docker exec failed: {e}"))?
            }
            ScannerMode::LocalBinary => {
                let path = self.config.binary_path.as_deref().unwrap_or("nuclei");
                Command::new(path)
                    .args([
                        "-target", target,
                        "-severity", severity_filter,
                        "-json", "-silent",
                        "-rate-limit", "50",
                        "-timeout", "5",
                    ])
                    .output()
                    .map_err(|e| format!("Nuclei failed: {e}"))?
            }
            ScannerMode::RemoteApi => {
                return Err("Nuclei does not support remote API mode".to_string());
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let findings = Self::parse_nuclei_json(&stdout);
        let duration = start.elapsed().as_secs_f64();

        Ok(ScanResult {
            scanner: "nuclei".to_string(),
            target: target.to_string(),
            findings,
            duration_secs: duration,
            error: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nuclei_json() {
        let output = r#"{"template-id":"cve-2024-1234","info":{"name":"Test CVE","severity":"critical","description":"Test","tags":["cve"],"reference":["https://example.com"]},"matched-at":"http://target:8080"}"#;
        let findings = NucleiScanner::parse_nuclei_json(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test CVE");
        assert_eq!(findings[0].severity, "critical");
        assert_eq!(findings[0].source, "nuclei");
    }

    #[test]
    fn test_parse_empty_output() {
        let findings = NucleiScanner::parse_nuclei_json("");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_parse_invalid_json() {
        let findings = NucleiScanner::parse_nuclei_json("not json\nalso not json");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_docker_config() {
        let scanner = NucleiScanner::docker("my-nuclei");
        assert_eq!(scanner.config.mode, ScannerMode::Docker);
        assert_eq!(scanner.config.container, Some("my-nuclei".to_string()));
    }

    #[test]
    fn test_local_config() {
        let scanner = NucleiScanner::local("/usr/bin/nuclei");
        assert_eq!(scanner.config.mode, ScannerMode::LocalBinary);
        assert_eq!(scanner.config.binary_path, Some("/usr/bin/nuclei".to_string()));
    }
}
