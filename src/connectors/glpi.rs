//! GLPI CMDB Connector — import assets from GLPI inventory.
//!
//! Auth: GET /apirest.php/initSession with App-Token + user_token
//! Computers: GET /apirest.php/Computer (paginated, 206 = more pages)
//! Network: GET /apirest.php/NetworkEquipment
//!
//! Feeds assets into the Asset Resolution Pipeline.

use crate::db::Database;
use crate::graph::asset_resolution::{self, DiscoveredAsset};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlpiConfig {
    /// GLPI URL (e.g., "https://glpi.corp.local")
    pub url: String,
    /// App-Token (configured in GLPI Setup > General > API)
    pub app_token: String,
    /// User token or empty for basic auth
    pub user_token: String,
    #[serde(default)]
    pub no_tls_verify: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlpiSyncResult {
    pub computers: usize,
    pub network_equipment: usize,
    pub assets_resolved: usize,
    pub errors: Vec<String>,
}

pub async fn sync_glpi(store: &dyn Database, config: &GlpiConfig) -> GlpiSyncResult {
    let mut result = GlpiSyncResult {
        computers: 0, network_equipment: 0, assets_resolved: 0, errors: vec![],
    };

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("HTTP client: {}", e)); return result; }
    };

    tracing::info!("GLPI: Connecting to {}", config.url);

    // Init session
    let session_url = format!("{}/apirest.php/initSession", config.url);
    let session_resp = match client.get(&session_url)
        .header("App-Token", &config.app_token)
        .header("Authorization", format!("user_token {}", config.user_token))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Session init: {}", e)); return result; }
    };

    if !session_resp.status().is_success() {
        result.errors.push(format!("Session HTTP {}", session_resp.status()));
        return result;
    }

    let session: serde_json::Value = match session_resp.json().await {
        Ok(s) => s,
        Err(e) => { result.errors.push(format!("Session parse: {}", e)); return result; }
    };

    let session_token = match session["session_token"].as_str() {
        Some(t) => t.to_string(),
        None => { result.errors.push("No session token".into()); return result; }
    };

    tracing::info!("GLPI: Session opened");

    // Fetch computers (paginated)
    let mut offset = 0;
    loop {
        let comp_url = format!("{}/apirest.php/Computer?range={}-{}&expand_dropdowns=true",
            config.url, offset, offset + 49);

        let resp = match client.get(&comp_url)
            .header("App-Token", &config.app_token)
            .header("Session-Token", &session_token)
            .send().await
        {
            Ok(r) => r,
            Err(e) => { result.errors.push(format!("Computers fetch: {}", e)); break; }
        };

        let is_partial = resp.status().as_u16() == 206;
        let is_ok = resp.status().is_success() || is_partial;

        if !is_ok { break; }

        let computers: Vec<serde_json::Value> = match resp.json().await {
            Ok(c) => c,
            Err(_) => break,
        };

        if computers.is_empty() { break; }

        for comp in &computers {
            let name = comp["name"].as_str().unwrap_or("").to_string();
            let serial = comp["serial"].as_str().map(String::from);
            let os = comp["operatingsystems_id"].as_str().map(String::from);
            let uuid = comp["uuid"].as_str().map(String::from);
            let is_deleted = comp["is_deleted"].as_i64().unwrap_or(0) != 0;

            if name.is_empty() || is_deleted { continue; }

            let discovered = DiscoveredAsset {
                mac: None,
                hostname: Some(name),
                fqdn: None,
                ip: None, // GLPI doesn't expose IP directly on Computer
                os,
                ports: None,
                ou: None,
                vlan: None,
                vm_id: uuid,
                criticality: None,
            services: serde_json::json!([]),
                source: "glpi".into(),
            };

            asset_resolution::resolve_asset(store, &discovered).await;
            result.assets_resolved += 1;
            result.computers += 1;
        }

        if !is_partial { break; } // 200 = last page
        offset += 50;
        if offset > 5000 { break; } // Safety limit
    }

    // Fetch network equipment
    let net_url = format!("{}/apirest.php/NetworkEquipment?range=0-99&expand_dropdowns=true", config.url);
    if let Ok(resp) = client.get(&net_url)
        .header("App-Token", &config.app_token)
        .header("Session-Token", &session_token)
        .send().await
    {
        if resp.status().is_success() || resp.status().as_u16() == 206 {
            if let Ok(equipment) = resp.json::<Vec<serde_json::Value>>().await {
                for eq in &equipment {
                    let name = eq["name"].as_str().unwrap_or("").to_string();
                    let is_deleted = eq["is_deleted"].as_i64().unwrap_or(0) != 0;

                    if name.is_empty() || is_deleted { continue; }

                    let discovered = DiscoveredAsset {
                        mac: None,
                        hostname: Some(name),
                        fqdn: None,
                        ip: None,
                        os: Some("Network Equipment".into()),
                        ports: None,
                        ou: None,
                        vlan: None,
                        vm_id: None,
                        criticality: Some("high".into()),
            services: serde_json::json!([]),
                        source: "glpi".into(),
                    };

                    asset_resolution::resolve_asset(store, &discovered).await;
                    result.assets_resolved += 1;
                    result.network_equipment += 1;
                }
            }
        }
    }

    // Kill session
    let kill_url = format!("{}/apirest.php/killSession", config.url);
    let _ = client.get(&kill_url)
        .header("App-Token", &config.app_token)
        .header("Session-Token", &session_token)
        .send().await;

    tracing::info!("GLPI SYNC: {} computers, {} network equipment, {} assets resolved",
        result.computers, result.network_equipment, result.assets_resolved);

    result
}

/// Create a GLPI ticket from a ThreatClaw finding.
pub async fn create_ticket(
    config: &GlpiConfig,
    title: &str,
    description: &str,
    urgency: u8, // 1=very low, 5=very high
) -> Result<serde_json::Value, String> {
    let client = Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;

    // Init session
    let session_url = format!("{}/apirest.php/initSession", config.url);
    let session_resp = client.get(&session_url)
        .header("App-Token", &config.app_token)
        .header("Authorization", format!("user_token {}", config.user_token))
        .send().await
        .map_err(|e| format!("Session: {}", e))?;

    if !session_resp.status().is_success() {
        return Err(format!("Session HTTP {}", session_resp.status()));
    }

    let session: serde_json::Value = session_resp.json().await.map_err(|e| format!("Parse: {}", e))?;
    let session_token = session["session_token"].as_str()
        .ok_or("No session token")?
        .to_string();

    // Create ticket
    let ticket_url = format!("{}/apirest.php/Ticket", config.url);
    let ticket_body = serde_json::json!({
        "input": {
            "name": title,
            "content": description,
            "urgency": urgency,
            "type": 1, // 1=incident
            "status": 1, // 1=new
            "itilcategories_id": 0,
        }
    });

    let resp = client.post(&ticket_url)
        .header("App-Token", &config.app_token)
        .header("Session-Token", &session_token)
        .header("Content-Type", "application/json")
        .json(&ticket_body)
        .send().await
        .map_err(|e| format!("Ticket create: {}", e))?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_default();

    // Kill session
    let kill_url = format!("{}/apirest.php/killSession", config.url);
    let _ = client.get(&kill_url)
        .header("App-Token", &config.app_token)
        .header("Session-Token", &session_token)
        .send().await;

    if status.is_success() || status.as_u16() == 201 {
        let ticket_id = body["id"].as_i64().unwrap_or(0);
        tracing::info!("GLPI: Ticket #{} created: {}", ticket_id, title);
        Ok(serde_json::json!({"ticket_id": ticket_id, "title": title, "success": true}))
    } else {
        Err(format!("GLPI ticket error: HTTP {} — {:?}", status, body))
    }
}
