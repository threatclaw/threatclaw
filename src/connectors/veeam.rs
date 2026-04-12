//! Veeam Backup & Replication Connector — monitor backup sessions and malware.
//!
//! Auth: OAuth2 password grant → Bearer token
//! Sessions: GET /api/v1/sessions
//! Malware: GET /api/v1/malwareDetection/detectedObjects (v12+)
//! Port: 9419 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeeamConfig {
    pub url: String,
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_sessions: u32,
}

fn default_true() -> bool { true }
fn default_limit() -> u32 { 100 }

#[derive(Debug, Clone, Serialize)]
pub struct VeeamSyncResult {
    pub sessions_checked: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_veeam(store: &dyn Database, config: &VeeamConfig) -> VeeamSyncResult {
    let mut result = VeeamSyncResult {
        sessions_checked: 0, findings_created: 0, errors: vec![],
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
    tracing::info!("VEEAM: Connecting to {}", url);

    // OAuth2 token
    let token_resp = match client.post(format!("{}/api/oauth2/token", url))
        .header("x-api-version", "1.1-rev2")
        .form(&[
            ("grant_type", "password"),
            ("username", &config.username),
            ("password", &config.password),
        ])
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Auth: {}", e)); return result; }
    };

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let text = token_resp.text().await.unwrap_or_default();
        result.errors.push(format!("Auth HTTP {}: {}", status, &text[..text.len().min(200)]));
        return result;
    }

    let token_data: serde_json::Value = match token_resp.json().await {
        Ok(d) => d,
        Err(e) => { result.errors.push(format!("Parse token: {}", e)); return result; }
    };

    let token = match token_data["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => { result.errors.push("No access_token".into()); return result; }
    };

    tracing::info!("VEEAM: Authenticated");

    // Fetch backup sessions
    let sessions_url = format!("{}/api/v1/sessions?limit={}&orderAsc=false", url, config.max_sessions);
    match client.get(&sessions_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("x-api-version", "1.1-rev2")
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(sessions) = data["data"].as_array() {
                    tracing::info!("VEEAM: {} sessions found", sessions.len());

                    for session in sessions {
                        let name = session["name"].as_str().unwrap_or("Unknown job");
                        let session_result = session["result"]["result"].as_str()
                            .or_else(|| session["result"].as_str())
                            .unwrap_or("");
                        let state = session["state"].as_str().unwrap_or("");
                        let session_type = session["sessionType"].as_str().unwrap_or("");
                        let end_time = session["endTime"].as_str().unwrap_or("");

                        result.sessions_checked += 1;

                        let (severity, should_create) = match session_result {
                            "Failed" => ("HIGH", true),
                            "Warning" => ("MEDIUM", true),
                            _ => ("LOW", false),
                        };

                        if should_create {
                            let _ = store.insert_finding(&NewFinding {
                                skill_id: "skill-veeam".into(),
                                title: format!("[Veeam] {} — {}", name, session_result),
                                description: Some(format!("Type: {}, State: {}, Ended: {}", session_type, state, end_time)),
                                severity: severity.into(),
                                category: Some("backup".into()),
                                asset: None,
                                source: Some("Veeam Backup".into()),
                                metadata: Some(serde_json::json!({
                                    "job_name": name,
                                    "result": session_result,
                                    "state": state,
                                    "session_type": session_type,
                                    "end_time": end_time,
                                })),
                            }).await;
                            result.findings_created += 1;
                        }
                    }
                }
            }
        }
        Ok(resp) => {
            result.errors.push(format!("Sessions HTTP {}", resp.status()));
        }
        Err(e) => {
            result.errors.push(format!("Sessions request: {}", e));
        }
    }

    // Check malware detection (v12+ feature, may 404 on older versions)
    let malware_url = format!("{}/api/v1/malwareDetection/detectedObjects", url);
    match client.get(&malware_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("x-api-version", "1.1-rev2")
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(detections) = data["data"].as_array() {
                    for detection in detections {
                        let obj_name = detection["objectName"].as_str().unwrap_or("unknown");
                        let malware_name = detection["malwareName"].as_str().unwrap_or("unknown");
                        let machine = detection["machineName"].as_str().unwrap_or("");

                        let _ = store.insert_finding(&NewFinding {
                            skill_id: "skill-veeam".into(),
                            title: format!("[Veeam] Malware '{}' in backup of {}", malware_name, obj_name),
                            description: Some(format!("Machine: {}", machine)),
                            severity: "CRITICAL".into(),
                            category: Some("malware".into()),
                            asset: if machine.is_empty() { None } else { Some(machine.to_string()) },
                            source: Some("Veeam Malware Detection".into()),
                            metadata: Some(serde_json::json!({
                                "object_name": obj_name,
                                "malware_name": malware_name,
                                "machine": machine,
                            })),
                        }).await;
                        result.findings_created += 1;
                    }
                }
            }
        }
        Ok(resp) if resp.status().as_u16() == 404 => {
            tracing::info!("VEEAM: Malware detection API not available (Veeam < 12)");
        }
        _ => {}
    }

    // Check repository usage
    let repo_url = format!("{}/api/v1/backupInfrastructure/repositories", url);
    match client.get(&repo_url)
        .header("Authorization", format!("Bearer {}", token))
        .header("x-api-version", "1.1-rev2")
        .send().await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(repos) = data["data"].as_array() {
                    for repo in repos {
                        let name = repo["name"].as_str().unwrap_or("unknown");
                        let capacity = repo["capacityGB"].as_f64().unwrap_or(0.0);
                        let free = repo["freeGB"].as_f64().unwrap_or(0.0);

                        if capacity > 0.0 {
                            let used_pct = ((capacity - free) / capacity * 100.0) as u32;
                            if used_pct >= 90 {
                                let _ = store.insert_finding(&NewFinding {
                                    skill_id: "skill-veeam".into(),
                                    title: format!("[Veeam] Repository '{}' {}% full", name, used_pct),
                                    description: Some(format!("Free: {:.1} GB / {:.1} GB total", free, capacity)),
                                    severity: if used_pct >= 95 { "HIGH" } else { "MEDIUM" }.into(),
                                    category: Some("backup".into()),
                                    asset: None,
                                    source: Some("Veeam Backup".into()),
                                    metadata: Some(serde_json::json!({
                                        "repository": name,
                                        "used_pct": used_pct,
                                        "capacity_gb": capacity,
                                        "free_gb": free,
                                    })),
                                }).await;
                                result.findings_created += 1;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    tracing::info!("VEEAM: Sync done — {} sessions, {} findings", result.sessions_checked, result.findings_created);
    result
}
