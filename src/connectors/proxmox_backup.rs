//! Proxmox Backup Server Connector — monitor backup jobs and verification.
//!
//! Auth: Ticket-based (POST /api2/json/access/ticket) or API token
//! Tasks: GET /api2/json/nodes/localhost/tasks
//! Datastore: GET /api2/json/status/datastore-usage
//! Port: 8007 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxBackupConfig {
    pub url: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub token_name: Option<String>,
    #[serde(default)]
    pub token_value: Option<String>,
    #[serde(default)]
    pub datastore: Option<String>,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxmoxBackupSyncResult {
    pub tasks_checked: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

enum PbsAuth {
    Ticket { ticket: String, csrf: String },
    Token(String),
}

pub async fn sync_proxmox_backup(
    store: &dyn Database,
    config: &ProxmoxBackupConfig,
) -> ProxmoxBackupSyncResult {
    let mut result = ProxmoxBackupSyncResult {
        tasks_checked: 0,
        findings_created: 0,
        errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client: {}", e));
            return result;
        }
    };

    let url = config.url.trim_end_matches('/');
    tracing::info!("PBS: Connecting to {}", url);

    // Authenticate
    let auth = if let (Some(name), Some(value)) = (&config.token_name, &config.token_value) {
        PbsAuth::Token(format!("PBSAPIToken={}:{}", name, value))
    } else if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        let resp = match client
            .post(format!("{}/api2/json/access/ticket", url))
            .form(&[("username", user.as_str()), ("password", pass.as_str())])
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Auth: {}", e));
                return result;
            }
        };

        if !resp.status().is_success() {
            result.errors.push(format!("Auth HTTP {}", resp.status()));
            return result;
        }

        let data: serde_json::Value = match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                result.errors.push(format!("Auth parse: {}", e));
                return result;
            }
        };

        let ticket = data["data"]["ticket"].as_str().unwrap_or("").to_string();
        let csrf = data["data"]["CSRFPreventionToken"]
            .as_str()
            .unwrap_or("")
            .to_string();

        if ticket.is_empty() {
            result.errors.push("No ticket in auth response".into());
            return result;
        }

        PbsAuth::Ticket { ticket, csrf }
    } else {
        result
            .errors
            .push("No auth: set username+password or token_name+token_value".into());
        return result;
    };

    tracing::info!("PBS: Authenticated");

    // Helper to add auth headers
    let add_auth = |req: reqwest::RequestBuilder| -> reqwest::RequestBuilder {
        match &auth {
            PbsAuth::Token(t) => req.header("Authorization", t.as_str()),
            PbsAuth::Ticket { ticket, csrf } => req
                .header("Cookie", format!("PBSAuthCookie={}", ticket))
                .header("CSRFPreventionToken", csrf.as_str()),
        }
    };

    // Fetch failed tasks
    let tasks_url = format!(
        "{}/api2/json/nodes/localhost/tasks?limit=100&statusfilter=error",
        url
    );
    match add_auth(client.get(&tasks_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(tasks) = data["data"].as_array() {
                    tracing::info!("PBS: {} failed tasks", tasks.len());

                    for task in tasks {
                        let task_type = task["worker_type"].as_str().unwrap_or("");
                        let worker_id = task["worker_id"].as_str().unwrap_or("");
                        let status = task["status"].as_str().unwrap_or("");
                        let upid = task["upid"].as_str().unwrap_or("");

                        result.tasks_checked += 1;

                        // Backup or verification failure
                        let severity =
                            if task_type.contains("backup") || task_type.contains("verify") {
                                "HIGH"
                            } else {
                                "MEDIUM"
                            };

                        let _ = store
                            .insert_finding(&NewFinding {
                                skill_id: "skill-proxmox-backup".into(),
                                title: format!("[PBS] {} failed: {}", task_type, worker_id),
                                description: Some(format!("Status: {}. UPID: {}", status, upid)),
                                severity: severity.into(),
                                category: Some("backup".into()),
                                asset: None,
                                source: Some("Proxmox Backup Server".into()),
                                metadata: Some(serde_json::json!({
                                    "task_type": task_type,
                                    "worker_id": worker_id,
                                    "status": status,
                                    "upid": upid,
                                })),
                            })
                            .await;
                        result.findings_created += 1;
                    }
                }
            }
        }
        Ok(resp) => {
            result.errors.push(format!("Tasks HTTP {}", resp.status()));
        }
        Err(e) => {
            result.errors.push(format!("Tasks request: {}", e));
        }
    }

    // Check datastore usage
    let ds_url = format!("{}/api2/json/status/datastore-usage", url);
    match add_auth(client.get(&ds_url)).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(stores) = data["data"].as_array() {
                    for ds in stores {
                        let name = ds["store"].as_str().unwrap_or("unknown");
                        let total = ds["total"].as_f64().unwrap_or(0.0);
                        let used = ds["used"].as_f64().unwrap_or(0.0);

                        if total > 0.0 {
                            let pct = (used / total * 100.0) as u32;
                            if pct >= 90 {
                                let _ = store
                                    .insert_finding(&NewFinding {
                                        skill_id: "skill-proxmox-backup".into(),
                                        title: format!("[PBS] Datastore '{}' {}% full", name, pct),
                                        description: Some(format!(
                                            "Used: {:.1} GB / {:.1} GB",
                                            used / 1e9,
                                            total / 1e9
                                        )),
                                        severity: if pct >= 95 { "HIGH" } else { "MEDIUM" }.into(),
                                        category: Some("backup".into()),
                                        asset: None,
                                        source: Some("Proxmox Backup Server".into()),
                                        metadata: Some(serde_json::json!({
                                            "datastore": name,
                                            "used_pct": pct,
                                            "total_bytes": total,
                                            "used_bytes": used,
                                        })),
                                    })
                                    .await;
                                result.findings_created += 1;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    tracing::info!(
        "PBS: Sync done — {} tasks, {} findings",
        result.tasks_checked,
        result.findings_created
    );
    result
}
