//! Scanner backend trait and common types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// How the scanner connects to the underlying tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerMode {
    /// ThreatClaw manages the Docker container.
    Docker,
    /// Tool is already installed locally.
    LocalBinary,
    /// Tool is running on a remote server.
    RemoteApi,
}

impl Default for ScannerMode {
    fn default() -> Self {
        Self::Docker
    }
}

/// Configuration for a scanner tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// How to connect to the tool.
    pub mode: ScannerMode,
    /// Docker container name (for mode=docker).
    pub container: Option<String>,
    /// Path to binary (for mode=local_binary).
    pub binary_path: Option<String>,
    /// Remote API URL (for mode=remote_api).
    pub url: Option<String>,
    /// API key vault reference (for mode=remote_api).
    pub api_key_vault: Option<String>,
    /// Whether this scanner is enabled.
    pub enabled: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            mode: ScannerMode::Docker,
            container: None,
            binary_path: None,
            url: None,
            api_key_vault: None,
            enabled: true,
        }
    }
}

/// Result of a scan operation.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub scanner: String,
    pub target: String,
    pub findings: Vec<ScanFinding>,
    pub duration_secs: f64,
    pub error: Option<String>,
}

/// A single finding from a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub title: String,
    pub severity: String,
    pub asset: String,
    pub source: String,
    pub description: Option<String>,
    pub metadata: serde_json::Value,
}

/// Trait for scanner backends — all scanners implement this.
#[async_trait]
pub trait ScannerBackend: Send + Sync {
    /// Name of the scanner (e.g., "nuclei", "trivy").
    fn name(&self) -> &str;

    /// Check if the scanner is available and responding.
    async fn health_check(&self) -> Result<String, String>;

    /// Run a scan against the specified target.
    async fn scan(&self, target: &str, options: &serde_json::Value) -> Result<ScanResult, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ScannerConfig::default();
        assert_eq!(config.mode, ScannerMode::Docker);
        assert!(config.enabled);
        assert!(config.container.is_none());
    }

    #[test]
    fn test_scanner_mode_serialize() {
        let mode = ScannerMode::LocalBinary;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"local_binary\"");

        let parsed: ScannerMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ScannerMode::LocalBinary);
    }

    #[test]
    fn test_scan_finding_serialize() {
        let finding = ScanFinding {
            title: "CVE-2024-1234".to_string(),
            severity: "critical".to_string(),
            asset: "192.168.1.10".to_string(),
            source: "nuclei".to_string(),
            description: Some("RCE vulnerability".to_string()),
            metadata: serde_json::json!({"template": "cve-2024-1234"}),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("CVE-2024-1234"));
    }
}
