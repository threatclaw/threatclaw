//! Authentik IAM Connector — import authentication events via REST API.
//!
//! Auth: Bearer token
//! Events: GET /api/v3/events/events/
//! Port: 9443 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthentikConfig {
    pub url: String,
    pub token: String,
    #[serde(default = "default_true")]
    pub no_tls_verify: bool,
    #[serde(default = "default_limit")]
    pub max_events: u32,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u32 {
    200
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthentikSyncResult {
    pub events_imported: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_authentik(store: &dyn Database, config: &AuthentikConfig) -> AuthentikSyncResult {
    let mut result = AuthentikSyncResult {
        events_imported: 0,
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
    tracing::info!("AUTHENTIK: Connecting to {}", url);

    // Fetch events
    let events_url = format!(
        "{}/api/v3/events/events/?ordering=-created&page_size={}",
        url, config.max_events
    );
    let resp = match client
        .get(&events_url)
        .header("Authorization", format!("Bearer {}", config.token))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Events request: {}", e));
            return result;
        }
    };

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        result.errors.push(format!(
            "Events HTTP {}: {}",
            status,
            &text[..text.len().min(200)]
        ));
        return result;
    }

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            result.errors.push(format!("Parse events: {}", e));
            return result;
        }
    };

    let events = match data["results"].as_array() {
        Some(e) => e,
        None => {
            tracing::info!("AUTHENTIK: No events found");
            return result;
        }
    };

    tracing::info!("AUTHENTIK: {} events found", events.len());

    // Track login failures per IP
    let mut failures_per_ip: HashMap<String, usize> = HashMap::new();

    for event in events {
        let action = event["action"].as_str().unwrap_or("");
        let username = event["user"]["username"].as_str().unwrap_or("");
        let client_ip = event["client_ip"].as_str().unwrap_or("");
        let created = event["created"].as_str().unwrap_or("");

        result.events_imported += 1;

        match action {
            "login_failed" => {
                *failures_per_ip.entry(client_ip.to_string()).or_insert(0) += 1;

                let _ = store
                    .insert_sigma_alert(
                        "authentik-login-failed",
                        "LOW",
                        &format!("Authentik login failed for {} from {}", username, client_ip),
                        "",
                        Some(client_ip),
                        Some(username),
                    )
                    .await;
            }
            "suspicious_request" => {
                let _ = store
                    .insert_finding(&NewFinding {
                        skill_id: "skill-authentik".into(),
                        title: format!("[Authentik] Suspicious request from {}", client_ip),
                        description: Some(format!("User: {}, Time: {}", username, created)),
                        severity: "HIGH".into(),
                        category: Some("iam".into()),
                        asset: None,
                        source: Some("Authentik IAM".into()),
                        metadata: Some(serde_json::json!({
                            "action": action,
                            "client_ip": client_ip,
                            "username": username,
                            "context": event["context"],
                        })),
                    })
                    .await;
                result.findings_created += 1;
            }
            "secret_view" => {
                let _ = store
                    .insert_finding(&NewFinding {
                        skill_id: "skill-authentik".into(),
                        title: format!("[Authentik] Secret viewed by {}", username),
                        description: Some(format!("IP: {}, Time: {}", client_ip, created)),
                        severity: "MEDIUM".into(),
                        category: Some("iam".into()),
                        asset: None,
                        source: Some("Authentik IAM".into()),
                        metadata: Some(serde_json::json!({
                            "action": action,
                            "client_ip": client_ip,
                            "username": username,
                        })),
                    })
                    .await;
                result.findings_created += 1;
            }
            "model_created" | "model_updated" | "model_deleted" => {
                let context = &event["context"];
                let model_name = context["model"]["model_name"].as_str().unwrap_or("");

                // Only track user/group changes
                if model_name == "user" || model_name == "group" || model_name == "token" {
                    let severity = if action == "model_deleted" {
                        "MEDIUM"
                    } else {
                        "LOW"
                    };
                    let _ = store
                        .insert_finding(&NewFinding {
                            skill_id: "skill-authentik".into(),
                            title: format!("[Authentik] {} {} by {}", action, model_name, username),
                            description: Some(format!("IP: {}, Time: {}", client_ip, created)),
                            severity: severity.into(),
                            category: Some("iam".into()),
                            asset: None,
                            source: Some("Authentik IAM".into()),
                            metadata: Some(serde_json::json!({
                                "action": action,
                                "model_name": model_name,
                                "client_ip": client_ip,
                                "username": username,
                            })),
                        })
                        .await;
                    result.findings_created += 1;
                }
            }
            "password_set" => {
                let _ = store
                    .insert_finding(&NewFinding {
                        skill_id: "skill-authentik".into(),
                        title: format!("[Authentik] Password changed for {}", username),
                        description: Some(format!("IP: {}, Time: {}", client_ip, created)),
                        severity: "LOW".into(),
                        category: Some("iam".into()),
                        asset: None,
                        source: Some("Authentik IAM".into()),
                        metadata: Some(serde_json::json!({
                            "action": action,
                            "client_ip": client_ip,
                            "username": username,
                        })),
                    })
                    .await;
                result.findings_created += 1;
            }
            _ => {}
        }
    }

    // Brute force detection
    for (ip, count) in &failures_per_ip {
        if *count >= 5 {
            let _ = store
                .insert_finding(&NewFinding {
                    skill_id: "skill-authentik".into(),
                    title: format!("[Authentik] Brute force: {} failures from {}", count, ip),
                    description: Some(format!("{} failed login attempts from IP {}", count, ip)),
                    severity: "HIGH".into(),
                    category: Some("iam".into()),
                    asset: None,
                    source: Some("Authentik IAM".into()),
                    metadata: Some(serde_json::json!({
                        "source_ip": ip,
                        "failure_count": count,
                        "detection": "brute_force",
                    })),
                })
                .await;
            result.findings_created += 1;
        }
    }

    tracing::info!(
        "AUTHENTIK: Sync done — {} events, {} findings",
        result.events_imported,
        result.findings_created
    );
    result
}
