//! Keycloak IAM Connector — import auth events and admin actions via REST API.
//!
//! Auth: OAuth2 client_credentials → Bearer token
//! Login events: GET /admin/realms/{realm}/events
//! Admin events: GET /admin/realms/{realm}/admin-events
//! Port: 8443 (HTTPS by default)

use crate::db::Database;
use crate::db::threatclaw_store::NewFinding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeycloakConfig {
    pub url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_realm")]
    pub realm: String,
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
fn default_realm() -> String {
    "master".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct KeycloakSyncResult {
    pub login_events: usize,
    pub admin_events: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_keycloak(store: &dyn Database, config: &KeycloakConfig) -> KeycloakSyncResult {
    let mut result = KeycloakSyncResult {
        login_events: 0,
        admin_events: 0,
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
    tracing::info!("KEYCLOAK: Connecting to {}", url);

    // OAuth2 client_credentials auth
    let token_url = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        url, config.realm
    );
    let mut form = HashMap::new();
    form.insert("grant_type", "client_credentials");
    form.insert("client_id", &config.client_id);
    form.insert("client_secret", &config.client_secret);

    let token_resp = match client.post(&token_url).form(&form).send().await {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Token request: {}", e));
            return result;
        }
    };

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let text = token_resp.text().await.unwrap_or_default();
        result.errors.push(format!(
            "Auth HTTP {}: {}",
            status,
            &text[..text.len().min(200)]
        ));
        return result;
    }

    let token_data: serde_json::Value = match token_resp.json().await {
        Ok(d) => d,
        Err(e) => {
            result.errors.push(format!("Parse token: {}", e));
            return result;
        }
    };

    let access_token = match token_data["access_token"].as_str() {
        Some(t) => t.to_string(),
        None => {
            result.errors.push("No access_token in response".into());
            return result;
        }
    };

    tracing::info!("KEYCLOAK: Authenticated");

    // Fetch login events
    let events_url = format!(
        "{}/admin/realms/{}/events?first=0&max={}",
        url, config.realm, config.max_events
    );
    match client
        .get(&events_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(events) = resp.json::<Vec<serde_json::Value>>().await {
                tracing::info!("KEYCLOAK: {} login events", events.len());

                // Track failures per IP for brute force detection
                let mut failures_per_ip: HashMap<String, usize> = HashMap::new();

                for event in &events {
                    let event_type = event["type"].as_str().unwrap_or("");
                    let ip = event["ipAddress"].as_str().unwrap_or("");
                    let user_id = event["userId"].as_str().unwrap_or("");
                    let client_id = event["clientId"].as_str().unwrap_or("");
                    let error = event["error"].as_str();

                    if event_type == "LOGIN_ERROR" {
                        *failures_per_ip.entry(ip.to_string()).or_insert(0) += 1;

                        let _ = store
                            .insert_sigma_alert(
                                "keycloak-login-error",
                                "LOW",
                                &format!("Keycloak login failed for {} from {}", user_id, ip),
                                "",
                                Some(ip),
                                Some(user_id),
                            )
                            .await;
                        result.login_events += 1;
                    } else if event_type == "LOGIN" {
                        result.login_events += 1;
                    } else if event_type == "REGISTER" {
                        let _ = store
                            .insert_finding(&NewFinding {
                                skill_id: "skill-keycloak".into(),
                                title: format!("[Keycloak] New user registration from {}", ip),
                                description: Some(format!(
                                    "User {} registered via client {}",
                                    user_id, client_id
                                )),
                                severity: "LOW".into(),
                                category: Some("iam".into()),
                                asset: None,
                                source: Some("Keycloak IAM".into()),
                                metadata: Some(serde_json::json!({
                                    "event_type": event_type,
                                    "ip": ip,
                                    "user_id": user_id,
                                    "client_id": client_id,
                                    "error": error,
                                })),
                            })
                            .await;
                        result.findings_created += 1;
                        result.login_events += 1;
                    }
                }

                // Brute force detection: >5 failures from same IP
                for (ip, count) in &failures_per_ip {
                    if *count >= 5 {
                        let _ = store
                            .insert_finding(&NewFinding {
                                skill_id: "skill-keycloak".into(),
                                title: format!(
                                    "[Keycloak] Brute force: {} failures from {}",
                                    count, ip
                                ),
                                description: Some(format!(
                                    "{} failed login attempts from IP {} in last sync window",
                                    count, ip
                                )),
                                severity: "HIGH".into(),
                                category: Some("iam".into()),
                                asset: None,
                                source: Some("Keycloak IAM".into()),
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
            }
        }
        Ok(resp) => {
            result.errors.push(format!("Events HTTP {}", resp.status()));
        }
        Err(e) => {
            result.errors.push(format!("Events request: {}", e));
        }
    }

    // Fetch admin events
    let admin_url = format!(
        "{}/admin/realms/{}/admin-events?first=0&max={}",
        url, config.realm, config.max_events
    );
    match client
        .get(&admin_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(events) = resp.json::<Vec<serde_json::Value>>().await {
                tracing::info!("KEYCLOAK: {} admin events", events.len());

                for event in &events {
                    let op = event["operationType"].as_str().unwrap_or("");
                    let resource = event["resourceType"].as_str().unwrap_or("");
                    let ip = event["authDetails"]["ipAddress"].as_str().unwrap_or("");
                    let user_id = event["authDetails"]["userId"].as_str().unwrap_or("");

                    let severity = match (op, resource) {
                        ("DELETE", "USER") | ("DELETE", "GROUP") | ("DELETE", "ROLE") => "HIGH",
                        ("CREATE", "USER") | ("CREATE", "ROLE") | ("UPDATE", "ROLE") => "MEDIUM",
                        _ => "LOW",
                    };

                    if severity != "LOW" {
                        let _ = store
                            .insert_finding(&NewFinding {
                                skill_id: "skill-keycloak".into(),
                                title: format!(
                                    "[Keycloak Admin] {} {} by {}",
                                    op, resource, user_id
                                ),
                                description: Some(format!("Admin action from IP {}", ip)),
                                severity: severity.into(),
                                category: Some("iam".into()),
                                asset: None,
                                source: Some("Keycloak Admin".into()),
                                metadata: Some(serde_json::json!({
                                    "operation": op,
                                    "resource_type": resource,
                                    "ip": ip,
                                    "user_id": user_id,
                                    "resource_path": event["resourcePath"],
                                })),
                            })
                            .await;
                        result.findings_created += 1;
                    }
                    result.admin_events += 1;
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("KEYCLOAK: Admin events: {}", e);
        }
    }

    tracing::info!(
        "KEYCLOAK: Sync done — {} login, {} admin, {} findings",
        result.login_events,
        result.admin_events,
        result.findings_created
    );
    result
}
