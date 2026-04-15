#![allow(unused_imports)]
//! UniFi Connector — import WiFi/network client inventory from UniFi Controller.
//!
//! API: POST /api/login → GET /api/s/{site}/stat/sta (active clients)
//! Auth: cookie-based session from login endpoint.
//! Discovers: MAC, IP, hostname, SSID, signal, traffic stats.

use crate::db::Database;
use crate::db::threatclaw_store::ThreatClawStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiConfig {
    pub url: String, // e.g. "https://192.168.1.1:8443"
    pub username: String,
    pub password: String,
    #[serde(default = "default_site")]
    pub site: String, // default "default"
    #[serde(default)]
    pub no_tls_verify: bool,
}

fn default_site() -> String {
    "default".into()
}

#[derive(Debug, Clone, Serialize)]
pub struct UnifiSyncResult {
    pub clients_discovered: usize,
    pub assets_created: usize,
    pub assets_updated: usize,
    pub errors: Vec<String>,
}

pub async fn sync_unifi(store: &dyn Database, config: &UnifiConfig) -> UnifiSyncResult {
    let mut result = UnifiSyncResult {
        clients_discovered: 0,
        assets_created: 0,
        assets_updated: 0,
        errors: vec![],
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.no_tls_verify)
        .cookie_store(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let base = config.url.trim_end_matches('/');

    // Login
    let login_resp = match client
        .post(&format!("{}/api/login", base))
        .json(&serde_json::json!({
            "username": config.username,
            "password": config.password,
        }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("UniFi login: {}", e));
            return result;
        }
    };

    if !login_resp.status().is_success() {
        result
            .errors
            .push(format!("UniFi login HTTP {}", login_resp.status()));
        return result;
    }

    // Get active clients
    let sta_resp = match client
        .get(&format!("{}/api/s/{}/stat/sta", base, config.site))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("UniFi clients: {}", e));
            return result;
        }
    };

    if !sta_resp.status().is_success() {
        result
            .errors
            .push(format!("UniFi clients HTTP {}", sta_resp.status()));
        return result;
    }

    let body: serde_json::Value = match sta_resp.json().await {
        Ok(b) => b,
        Err(e) => {
            result.errors.push(format!("UniFi parse: {}", e));
            return result;
        }
    };

    let clients_arr = body["data"].as_array();
    if let Some(clients) = clients_arr {
        for c in clients {
            result.clients_discovered += 1;

            let mac = c["mac"].as_str().unwrap_or("").to_string();
            let ip = c["ip"].as_str().unwrap_or("").to_string();
            let hostname = c["hostname"]
                .as_str()
                .or_else(|| c["name"].as_str())
                .unwrap_or("")
                .to_string();
            let oui = c["oui"].as_str().unwrap_or("").to_string();

            if mac.is_empty() {
                continue;
            }

            let discovered = crate::graph::asset_resolution::DiscoveredAsset {
                mac: Some(mac),
                hostname: if hostname.is_empty() {
                    None
                } else {
                    Some(hostname)
                },
                fqdn: None,
                ip: if ip.is_empty() { None } else { Some(ip) },
                os: None,
                ports: None,
                services: serde_json::json!([]),
                ou: None,
                vlan: None,
                vm_id: None,
                criticality: Some("low".into()),
                source: "unifi".into(),
            };
            let res = crate::graph::asset_resolution::resolve_asset(store, &discovered).await;
            tracing::debug!("UNIFI ASSET: {} → {:?}", res.asset_id, res.action);
            result.assets_created += 1;
        }
    }

    // Logout
    let _ = client.post(&format!("{}/api/logout", base)).send().await;

    tracing::info!(
        "UNIFI: {} clients discovered, {} assets created/updated",
        result.clients_discovered,
        result.assets_created
    );

    result
}
