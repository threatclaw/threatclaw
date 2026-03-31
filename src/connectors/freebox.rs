//! Freebox Connector — discover LAN assets via Freebox OS REST API.
//!
//! Works with all Freebox models (Revolution, Mini 4K, Pop, Delta, Ultra).
//! Auth: HMAC-SHA1 challenge-response, token stored permanently after one-time physical pairing.
//! Single call to /lan/browser/pub/ gives MAC, IP, hostname, vendor, device type, active status.

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewAsset};
use crate::graph::asset_resolution::{DiscoveredAsset, resolve_asset};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use serde::{Deserialize, Serialize};

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeboxConfig {
    pub url: String,          // "http://mafreebox.freebox.fr" or "http://192.168.1.254"
    pub app_token: String,    // Permanent token from pairing
}

#[derive(Debug, Clone, Serialize)]
pub struct FreeboxSyncResult {
    pub devices_found: usize,
    pub devices_active: usize,
    pub assets_created: usize,
    pub assets_updated: usize,
    pub new_devices: Vec<String>,
    pub errors: Vec<String>,
}

// ── API response types ──

#[derive(Debug, Deserialize)]
struct FreeboxApiResponse<T> {
    success: bool,
    result: Option<T>,
    error_code: Option<String>,
    msg: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FreeboxApiVersion {
    api_version: String,
    api_base_url: String,
}

#[derive(Debug, Deserialize)]
struct FreeboxLogin {
    challenge: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FreeboxSession {
    session_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FreeboxLanHost {
    id: Option<String>,
    primary_name: Option<String>,
    host_type: Option<String>,
    vendor_name: Option<String>,
    active: Option<bool>,
    reachable: Option<bool>,
    last_time_reachable: Option<i64>,
    last_activity: Option<i64>,
    l2ident: Option<FreeboxL2Ident>,
    l3connectivities: Option<Vec<FreeboxL3Conn>>,
    names: Option<Vec<FreeboxName>>,
}

#[derive(Debug, Deserialize)]
struct FreeboxL2Ident {
    id: Option<String>,  // MAC address
    #[serde(rename = "type")]
    ident_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FreeboxL3Conn {
    addr: Option<String>,
    af: Option<String>,     // "ipv4" or "ipv6"
    active: Option<bool>,
    reachable: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct FreeboxName {
    name: Option<String>,
    source: Option<String>,  // "dhcp", "netbios", "mdns", "upnp"
}

// ── Auth flow ──

async fn get_api_base(client: &reqwest::Client, base_url: &str) -> Result<String, String> {
    let url = format!("{}/api_version", base_url.trim_end_matches('/'));
    let resp: FreeboxApiVersion = client.get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send().await.map_err(|e| format!("Freebox unreachable: {e}"))?
        .json().await.map_err(|e| format!("Invalid API version response: {e}"))?;

    let major = resp.api_version.split('.').next().unwrap_or("4");
    Ok(format!("{}/api/v{}", base_url.trim_end_matches('/'), major))
}

async fn get_session_token(
    client: &reqwest::Client,
    api_base: &str,
    app_token: &str,
) -> Result<String, String> {
    // Step 1: Get challenge
    let login_resp: FreeboxApiResponse<FreeboxLogin> = client.get(&format!("{}/login/", api_base))
        .timeout(std::time::Duration::from_secs(5))
        .send().await.map_err(|e| format!("Login failed: {e}"))?
        .json().await.map_err(|e| format!("Invalid login response: {e}"))?;

    let challenge = login_resp.result
        .and_then(|r| r.challenge)
        .ok_or("No challenge in login response")?;

    // Step 2: Compute HMAC-SHA1(app_token, challenge)
    let mut mac = HmacSha1::new_from_slice(app_token.as_bytes())
        .map_err(|e| format!("HMAC init error: {e}"))?;
    mac.update(challenge.as_bytes());
    let password = hex::encode(mac.finalize().into_bytes());

    // Step 3: Open session
    let session_resp: FreeboxApiResponse<FreeboxSession> = client.post(&format!("{}/login/session/", api_base))
        .json(&serde_json::json!({
            "app_id": "fr.cyberconsulting.threatclaw",
            "password": password,
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send().await.map_err(|e| format!("Session failed: {e}"))?
        .json().await.map_err(|e| format!("Invalid session response: {e}"))?;

    if !session_resp.success {
        return Err(format!("Session denied: {} — {}",
            session_resp.error_code.unwrap_or_default(),
            session_resp.msg.unwrap_or_default()));
    }

    session_resp.result
        .and_then(|r| r.session_token)
        .ok_or("No session token in response".into())
}

// ── Pairing flow (one-time) ──

#[derive(Debug, Deserialize)]
struct FreeboxAuthorize {
    app_token: Option<String>,
    track_id: Option<i64>,
}

/// Request pairing with the Freebox. Returns (app_token, track_id).
/// The user must press the physical button on the Freebox.
pub async fn request_pairing(base_url: &str) -> Result<(String, i64), String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().map_err(|e| e.to_string())?;

    let api_base = get_api_base(&client, base_url).await?;

    let resp: FreeboxApiResponse<FreeboxAuthorize> = client.post(&format!("{}/login/authorize/", api_base))
        .json(&serde_json::json!({
            "app_id": "fr.cyberconsulting.threatclaw",
            "app_name": "ThreatClaw",
            "app_version": "2.0",
            "device_name": "ThreatClaw Server",
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send().await.map_err(|e| format!("Pairing request failed: {e}"))?
        .json().await.map_err(|e| format!("Invalid pairing response: {e}"))?;

    if !resp.success {
        return Err(format!("Pairing denied: {}", resp.msg.unwrap_or_default()));
    }

    let result = resp.result.ok_or("No pairing result")?;
    let token = result.app_token.ok_or("No app_token in response")?;
    let track_id = result.track_id.ok_or("No track_id in response")?;

    Ok((token, track_id))
}

/// Check pairing status. Returns "pending", "granted", "denied", "timeout", "unknown".
pub async fn check_pairing_status(base_url: &str, track_id: i64) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().map_err(|e| e.to_string())?;

    let api_base = get_api_base(&client, base_url).await?;

    let resp: FreeboxApiResponse<serde_json::Value> = client.get(&format!("{}/login/authorize/{}", api_base, track_id))
        .timeout(std::time::Duration::from_secs(5))
        .send().await.map_err(|e| format!("Status check failed: {e}"))?
        .json().await.map_err(|e| format!("Invalid status response: {e}"))?;

    Ok(resp.result
        .and_then(|r| r["status"].as_str().map(String::from))
        .unwrap_or("unknown".into()))
}

// ── Main sync function ──

/// Map Freebox host_type to ThreatClaw category.
fn freebox_type_to_category(host_type: &str) -> &'static str {
    match host_type {
        "workstation" | "laptop" => "workstation",
        "smartphone" | "tablet" => "mobile",
        "printer" => "printer",
        "nas" => "server",
        "ip_camera" => "camera",
        "ip_phone" => "iot",
        "television" | "vg_console" | "multimedia_device" | "freebox_player" | "freebox_hd" => "iot",
        "networking_device" => "network",
        _ => "unknown",
    }
}

/// Sync all LAN devices from Freebox into ThreatClaw assets.
pub async fn sync_freebox(store: &dyn Database, config: &FreeboxConfig) -> FreeboxSyncResult {
    let mut result = FreeboxSyncResult {
        devices_found: 0, devices_active: 0,
        assets_created: 0, assets_updated: 0,
        new_devices: vec![], errors: vec![],
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build().unwrap();

    let base_url = config.url.trim_end_matches('/');

    // Get API base URL
    let api_base = match get_api_base(&client, base_url).await {
        Ok(b) => b,
        Err(e) => { result.errors.push(e); return result; }
    };

    // Get session token
    let session_token = match get_session_token(&client, &api_base, &config.app_token).await {
        Ok(t) => t,
        Err(e) => { result.errors.push(e); return result; }
    };

    // Fetch all LAN hosts
    let hosts_resp: FreeboxApiResponse<Vec<FreeboxLanHost>> = match client
        .get(&format!("{}/lan/browser/pub/", api_base))
        .header("X-Fbx-App-Auth", &session_token)
        .send().await
    {
        Ok(r) => match r.json().await {
            Ok(j) => j,
            Err(e) => { result.errors.push(format!("JSON parse error: {e}")); return result; }
        },
        Err(e) => { result.errors.push(format!("LAN browser failed: {e}")); return result; }
    };

    if !hosts_resp.success {
        result.errors.push(format!("LAN browser error: {}", hosts_resp.msg.unwrap_or_default()));
        return result;
    }

    let hosts = hosts_resp.result.unwrap_or_default();
    result.devices_found = hosts.len();

    tracing::info!("FREEBOX: {} devices found on LAN", hosts.len());

    for host in &hosts {
        let mac = host.l2ident.as_ref().and_then(|l| l.id.clone());
        let is_active = host.active.unwrap_or(false);
        if is_active { result.devices_active += 1; }

        // Get best IPv4 address
        let ipv4 = host.l3connectivities.as_ref()
            .and_then(|conns| conns.iter()
                .find(|c| c.af.as_deref() == Some("ipv4") && c.active.unwrap_or(false))
                .or_else(|| conns.iter().find(|c| c.af.as_deref() == Some("ipv4")))
                .and_then(|c| c.addr.clone()));

        // Get best hostname from names list
        let hostname = host.names.as_ref()
            .and_then(|names| {
                // Prefer DHCP > mDNS > NetBIOS > UPnP > primary_name
                names.iter().find(|n| n.source.as_deref() == Some("dhcp"))
                    .or_else(|| names.iter().find(|n| n.source.as_deref() == Some("mdns")))
                    .or_else(|| names.iter().find(|n| n.source.as_deref() == Some("netbios")))
                    .or_else(|| names.iter().find(|n| n.source.as_deref() == Some("upnp")))
                    .or_else(|| names.first())
                    .and_then(|n| n.name.clone())
            })
            .or(host.primary_name.clone())
            .filter(|n| !n.is_empty() && n != "unknown");

        let vendor = host.vendor_name.clone().filter(|v| !v.is_empty());
        let host_type = host.host_type.as_deref().unwrap_or("other");
        let category = freebox_type_to_category(host_type);

        // Skip if no MAC (shouldn't happen but safety)
        if mac.is_none() && ipv4.is_none() { continue; }

        // Build name: hostname > vendor+suffix > type+suffix > ip
        let name = hostname.clone()
            .or_else(|| {
                let suffix = ipv4.as_ref().and_then(|ip| ip.rsplit('.').next().map(String::from)).unwrap_or_default();
                vendor.as_ref().map(|v| {
                    let short = v.split_whitespace().next().unwrap_or(v).trim_end_matches(',');
                    format!("{}-{}", short, suffix)
                })
            })
            .or_else(|| {
                let suffix = ipv4.as_ref().and_then(|ip| ip.rsplit('.').next().map(String::from)).unwrap_or_default();
                Some(format!("{}-{}", host_type, suffix))
            })
            .unwrap_or_else(|| "unknown".into());

        // Criticality from type
        let criticality = match category {
            "server" => "high",
            "network" => "high",
            "workstation" => "medium",
            "printer" => "low",
            "camera" => "medium",
            "mobile" => "low",
            "iot" => "low",
            _ => "low",
        };

        // Resolve via Asset Resolution Pipeline (MAC > hostname > IP merge)
        let discovered = DiscoveredAsset {
            mac: mac.clone(),
            hostname: hostname.clone(),
            fqdn: None,
            ip: ipv4.clone(),
            os: None,
            ports: None,
            services: serde_json::json!([]),
            ou: None,
            vlan: None,
            vm_id: None,
            criticality: Some(criticality.into()),
            source: "freebox".into(),
        };

        let resolution = resolve_asset(store, &discovered).await;

        match resolution.action {
            crate::graph::asset_resolution::ResolutionAction::Created => {
                result.assets_created += 1;
                result.new_devices.push(format!("{} ({}) — {}", name, ipv4.as_deref().unwrap_or("?"), vendor.as_deref().unwrap_or("?")));
                tracing::info!("FREEBOX: New device: {} [{}] {} ({})",
                    name, mac.as_deref().unwrap_or("?"), ipv4.as_deref().unwrap_or("?"), host_type);
            }
            crate::graph::asset_resolution::ResolutionAction::Merged |
            crate::graph::asset_resolution::ResolutionAction::Updated => {
                result.assets_updated += 1;
            }
            _ => {}
        }

        // Update mac_vendor in the asset if we have it from Freebox
        if let Some(ref v) = vendor {
            if let Some(ref ip) = ipv4 {
                // Direct SQL update for mac_vendor (not in NewAsset flow)
                let _ = store.set_setting("_asset_vendor", &format!("{}:{}", resolution.asset_id, v), &serde_json::json!(v)).await;
            }
        }
    }

    tracing::info!("FREEBOX SYNC COMPLETE: {} devices, {} active, {} new, {} updated",
        result.devices_found, result.devices_active, result.assets_created, result.assets_updated);

    result
}
