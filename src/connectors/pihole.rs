#![allow(unused_imports)]
//! Pi-hole Connector — import DNS queries from Pi-hole v6 API.
//!
//! Pi-hole v6 has a built-in REST API (no more lighttpd/PHP).
//! Endpoint: GET http://{host}/api/queries
//! Auth: requires session token from POST /api/auth

use crate::db::Database;
use crate::db::threatclaw_store::{ThreatClawStore, NewFinding};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiholeConfig {
    pub url: String,       // e.g. "http://192.168.1.1"
    pub password: String,  // Pi-hole admin password
}

#[derive(Debug, Clone, Serialize)]
pub struct PiholeSyncResult {
    pub queries_analyzed: usize,
    pub blocked_domains: usize,
    pub suspicious_domains: usize,
    pub clients_seen: usize,
    pub findings_created: usize,
    pub errors: Vec<String>,
}

pub async fn sync_pihole(store: &dyn Database, config: &PiholeConfig) -> PiholeSyncResult {
    let mut result = PiholeSyncResult {
        queries_analyzed: 0, blocked_domains: 0, suspicious_domains: 0,
        clients_seen: 0, findings_created: 0, errors: vec![],
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => { result.errors.push(format!("Pi-hole HTTP client: {}", e)); return result; }
    };
    let base = config.url.trim_end_matches('/');

    // Authenticate
    let auth_resp = match client.post(&format!("{}/api/auth", base))
        .json(&serde_json::json!({"password": config.password}))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Pi-hole auth: {}", e)); return result; }
    };

    if !auth_resp.status().is_success() {
        result.errors.push(format!("Pi-hole auth HTTP {}", auth_resp.status()));
        return result;
    }

    let auth_body: serde_json::Value = match auth_resp.json().await {
        Ok(b) => b,
        Err(e) => { result.errors.push(format!("Pi-hole auth parse: {}", e)); return result; }
    };

    let session = auth_body["session"]["sid"].as_str().unwrap_or("");
    if session.is_empty() {
        result.errors.push("Pi-hole: no session token".into());
        return result;
    }

    // Get recent queries
    let queries_resp = match client.get(&format!("{}/api/queries?length=200", base))
        .header("sid", session)
        .timeout(std::time::Duration::from_secs(15))
        .send().await
    {
        Ok(r) => r,
        Err(e) => { result.errors.push(format!("Pi-hole queries: {}", e)); return result; }
    };

    if !queries_resp.status().is_success() {
        result.errors.push(format!("Pi-hole queries HTTP {}", queries_resp.status()));
        return result;
    }

    let body: serde_json::Value = match queries_resp.json().await {
        Ok(b) => b,
        Err(e) => { result.errors.push(format!("Pi-hole parse: {}", e)); return result; }
    };

    let queries = body["queries"].as_array();
    let mut clients = std::collections::HashSet::new();
    let mut blocked = std::collections::HashSet::new();

    if let Some(arr) = queries {
        for q in arr {
            result.queries_analyzed += 1;
            let client_ip = q["client"].as_str().unwrap_or("");
            let domain = q["domain"].as_str().unwrap_or("");
            let status = q["status"].as_i64().unwrap_or(0);

            if !client_ip.is_empty() { clients.insert(client_ip.to_string()); }

            // Status 1 = blocked by gravity, 4 = blocked by regex, 5 = blocked by exact
            if status == 1 || status == 4 || status == 5 {
                blocked.insert(domain.to_string());
            }
        }
    }

    result.clients_seen = clients.len();
    result.blocked_domains = blocked.len();

    // Create findings for heavily blocked clients (>20 blocked queries = suspicious)
    let mut client_blocked_count: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    if let Some(arr) = queries {
        for q in arr {
            let client_ip = q["client"].as_str().unwrap_or("");
            let status = q["status"].as_i64().unwrap_or(0);
            if status == 1 || status == 4 || status == 5 {
                *client_blocked_count.entry(client_ip.to_string()).or_insert(0) += 1;
            }
        }
    }

    for (ip, count) in &client_blocked_count {
        if *count >= 20 {
            let title = format!("Pi-hole: {} blocked DNS queries from {}", count, ip);
            if store.insert_finding(&NewFinding {
                skill_id: "skill-pihole".into(),
                title,
                description: Some(format!("Client {} has {} blocked DNS queries in recent history", ip, count)),
                severity: "MEDIUM".into(),
                category: Some("dns-suspicious".into()),
                asset: Some(ip.clone()),
                source: Some("Pi-hole".into()),
                metadata: Some(serde_json::json!({"blocked_count": count, "client": ip})),
            }).await.is_ok() {
                result.findings_created += 1;
            }
        }
    }

    tracing::info!(
        "PIHOLE: {} queries, {} blocked domains, {} clients, {} findings",
        result.queries_analyzed, result.blocked_domains, result.clients_seen, result.findings_created
    );

    result
}
