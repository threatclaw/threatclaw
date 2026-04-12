//! Shuffle SOAR Connector — import workflow execution status via REST API.
//!
//! Auth: Bearer API key
//! Workflows: GET /api/v1/workflows
//! Executions: GET /api/v1/workflows/{id}/executions
//! Port: 3443 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShuffleConfig {
    pub url: String,
    pub api_key: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct ShuffleSyncResult {
    pub workflows_checked: usize,
    pub failures_found: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_shuffle(store: &dyn Database, config: &ShuffleConfig) -> ShuffleSyncResult {
    let mut result = ShuffleSyncResult {
        workflows_checked: 0, failures_found: 0, findings_created: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("SHUFFLE: Connecting to {}", url);

    // Fetch workflows
    let resp = match client.get(format!("{}/api/v1/workflows", url))
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Workflows request: {}", e)); return result; }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        result.errors.push(format!("Workflows HTTP {}: {}", status, &text[..text.len().min(200)]));
        return result;
    }

    let workflows: Vec<serde_json::Value> = match resp.json().await {
        Ok(w) => w,
        Err(e) => { result.errors.push(format!("Parse workflows: {}", e)); return result; }
    };

    tracing::info!("SHUFFLE: {} workflows found", workflows.len());

    for workflow in &workflows {
        let wf_id = match workflow["id"].as_str() {
            Some(id) => id,
            None => continue,
        };
        let wf_name = workflow["name"].as_str().unwrap_or("Unnamed workflow");
        result.workflows_checked += 1;

        // Fetch recent executions for this workflow
        let exec_resp = match client.get(format!("{}/api/v1/workflows/{}/executions", url, wf_id))
            .header("Authorization", format!("Bearer {}", config.api_key))
            .send().await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("SHUFFLE: Executions for {}: {}", wf_name, e);
                continue;
            }
        };

        if !exec_resp.status().is_success() {
            continue;
        }

        let executions: Vec<serde_json::Value> = match exec_resp.json().await {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Check last 10 executions for failures
        for exec in executions.iter().take(10) {
            let status = exec["status"].as_str().unwrap_or("");
            let exec_id = exec["execution_id"].as_str()
                .or_else(|| exec["id"].as_str())
                .unwrap_or("");
            let started = exec["started_at"].as_str().unwrap_or("");

            if status == "FAILURE" || status == "ABORTED" {
                result.failures_found += 1;

                let severity = if status == "FAILURE" { "HIGH" } else { "MEDIUM" };

                let _ = store.insert_finding(&NewFinding {
                    skill_id: "skill-shuffle".into(),
                    title: format!("[Shuffle] Workflow '{}' {}", wf_name, status.to_lowercase()),
                    description: Some(format!(
                        "Workflow '{}' execution {} — Status: {}. Started: {}",
                        wf_name, exec_id, status, started
                    )),
                    severity: severity.into(),
                    category: Some("soar".into()),
                    asset: None,
                    source: Some("Shuffle SOAR".into()),
                    metadata: Some(serde_json::json!({
                        "workflow_id": wf_id,
                        "workflow_name": wf_name,
                        "execution_id": exec_id,
                        "status": status,
                    })),
                }).await;
                result.findings_created += 1;
            }
        }
    }

    tracing::info!("SHUFFLE: Sync done — {} workflows, {} failures, {} findings",
        result.workflows_checked, result.failures_found, result.findings_created);
    result
}
