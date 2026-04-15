//! Trivy scanner — container and dependency vulnerability detection.
//!
//! Supports 3 modes:
//! - Docker: `docker exec <container> trivy ...`
//! - LocalBinary: `/usr/local/bin/trivy ...`
//! - RemoteApi: `GET http://<host>:4954/...` (Trivy server mode)

use async_trait::async_trait;
use std::process::Command;
use std::time::Instant;

use super::backend::*;

pub struct TrivyScanner {
    config: ScannerConfig,
}

impl TrivyScanner {
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

    pub fn remote(url: &str) -> Self {
        Self::new(ScannerConfig {
            mode: ScannerMode::RemoteApi,
            url: Some(url.to_string()),
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

    fn parse_trivy_json(output: &str) -> Vec<ScanFinding> {
        let v: serde_json::Value = match serde_json::from_str(output) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Trivy JSON output has Results[] → Vulnerabilities[]
        if let Some(results) = v["Results"].as_array() {
            for result in results {
                let target = result["Target"].as_str().unwrap_or("unknown");
                if let Some(vulns) = result["Vulnerabilities"].as_array() {
                    for vuln in vulns {
                        let vuln_id = vuln["VulnerabilityID"].as_str().unwrap_or("unknown");
                        let title = vuln["Title"].as_str().unwrap_or(vuln_id);
                        let severity = vuln["Severity"]
                            .as_str()
                            .unwrap_or("UNKNOWN")
                            .to_lowercase();
                        let pkg_name = vuln["PkgName"].as_str().unwrap_or("");
                        let installed = vuln["InstalledVersion"].as_str().unwrap_or("");
                        let fixed = vuln["FixedVersion"].as_str().unwrap_or("");
                        let description = vuln["Description"].as_str().map(|s| {
                            if s.len() > 300 {
                                format!("{}...", &s[..300])
                            } else {
                                s.to_string()
                            }
                        });

                        findings.push(ScanFinding {
                            title: format!("{} — {}", vuln_id, title),
                            severity,
                            asset: format!("{} ({})", target, pkg_name),
                            source: "trivy".to_string(),
                            description,
                            metadata: serde_json::json!({
                                "vuln_id": vuln_id,
                                "package": pkg_name,
                                "installed_version": installed,
                                "fixed_version": fixed,
                            }),
                        });
                    }
                }
            }
        }

        findings
    }
}

#[async_trait]
impl ScannerBackend for TrivyScanner {
    fn name(&self) -> &str {
        "trivy"
    }

    async fn health_check(&self) -> Result<String, String> {
        match &self.config.mode {
            ScannerMode::Docker => {
                let container = self.config.container.as_deref().unwrap_or("docker-trivy-1");
                let output = Command::new("docker")
                    .args(["exec", container, "trivy", "--version"])
                    .output()
                    .map_err(|e| format!("Docker exec failed: {e}"))?;
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            ScannerMode::LocalBinary => {
                let path = self.config.binary_path.as_deref().unwrap_or("trivy");
                let output = Command::new(path)
                    .arg("--version")
                    .output()
                    .map_err(|e| format!("Binary not found: {e}"))?;
                Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
            }
            ScannerMode::RemoteApi => {
                let url = self
                    .config
                    .url
                    .as_deref()
                    .unwrap_or("http://localhost:4954");
                let resp = reqwest::Client::new()
                    .get(format!("{}/healthz", url))
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                    .map_err(|e| format!("Trivy API unreachable: {e}"))?;
                if resp.status().is_success() {
                    Ok(format!("Trivy server at {}", url))
                } else {
                    Err(format!("Trivy returned {}", resp.status()))
                }
            }
        }
    }

    async fn scan(&self, target: &str, options: &serde_json::Value) -> Result<ScanResult, String> {
        let start = Instant::now();
        let scan_type = options["type"].as_str().unwrap_or("image");

        let output_str = match &self.config.mode {
            ScannerMode::Docker => {
                let container = self.config.container.as_deref().unwrap_or("docker-trivy-1");
                let output = Command::new("docker")
                    .args([
                        "exec", container, "trivy", scan_type, target, "--format", "json",
                        "--quiet",
                    ])
                    .output()
                    .map_err(|e| format!("Trivy scan failed: {e}"))?;
                String::from_utf8_lossy(&output.stdout).to_string()
            }
            ScannerMode::LocalBinary => {
                let path = self.config.binary_path.as_deref().unwrap_or("trivy");
                let output = Command::new(path)
                    .args([scan_type, target, "--format", "json", "--quiet"])
                    .output()
                    .map_err(|e| format!("Trivy scan failed: {e}"))?;
                String::from_utf8_lossy(&output.stdout).to_string()
            }
            ScannerMode::RemoteApi => {
                let url = self
                    .config
                    .url
                    .as_deref()
                    .unwrap_or("http://localhost:4954");
                let resp = reqwest::Client::new()
                    .post(format!("{}/scan", url))
                    .json(&serde_json::json!({ "target": target, "type": scan_type }))
                    .timeout(std::time::Duration::from_secs(120))
                    .send()
                    .await
                    .map_err(|e| format!("Trivy API error: {e}"))?;
                resp.text()
                    .await
                    .map_err(|e| format!("Response error: {e}"))?
            }
        };

        let findings = Self::parse_trivy_json(&output_str);
        let duration = start.elapsed().as_secs_f64();

        Ok(ScanResult {
            scanner: "trivy".to_string(),
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
    fn test_parse_trivy_json() {
        let output = r#"{
            "Results": [{
                "Target": "alpine:3.18",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-1234",
                    "Title": "Buffer overflow",
                    "Severity": "HIGH",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.1.0",
                    "FixedVersion": "3.1.1",
                    "Description": "A buffer overflow in OpenSSL"
                }]
            }]
        }"#;
        let findings = TrivyScanner::parse_trivy_json(output);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("CVE-2024-1234"));
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].source, "trivy");
    }

    #[test]
    fn test_parse_empty() {
        let findings = TrivyScanner::parse_trivy_json("{}");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_docker_config() {
        let scanner = TrivyScanner::docker("my-trivy");
        assert_eq!(scanner.config.mode, ScannerMode::Docker);
    }

    #[test]
    fn test_remote_config() {
        let scanner = TrivyScanner::remote("http://10.0.0.5:4954");
        assert_eq!(scanner.config.mode, ScannerMode::RemoteApi);
        assert_eq!(scanner.config.url, Some("http://10.0.0.5:4954".to_string()));
    }
}
