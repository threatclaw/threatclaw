// See ADR-044: Olvid — messagerie certifiée ANSSI (CSPN)
//
// Architecture: ThreatClaw → HTTP bridge → Olvid daemon (gRPC)
// Le daemon Olvid expose une API gRPC (protobuf). Ce module communique
// via un bridge HTTP local (olvid-bridge container ou grpc-web-proxy).
// Quand tonic sera ajouté au projet, ce module pourra parler gRPC direct.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OlvidConfig {
    pub enabled: bool,
    pub daemon_url: String,
    pub client_key: String,
    pub discussion_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OlvidSendRequest {
    client_key: String,
    discussion_id: String,
    body: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OlvidStatusResponse {
    pub connected: bool,
    pub identity: Option<String>,
    pub error: Option<String>,
}

/// Send a message to an Olvid discussion via the bridge.
pub async fn send_message(
    daemon_url: &str,
    client_key: &str,
    discussion_id: &str,
    message: &str,
) -> Result<(), String> {
    let url = format!("{}/v1/message/send", daemon_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let payload = OlvidSendRequest {
        client_key: client_key.to_string(),
        discussion_id: discussion_id.to_string(),
        body: message.to_string(),
    };

    let resp = client.post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Olvid daemon unreachable: {e}"))?;

    if resp.status().is_success() {
        tracing::info!("OLVID: Message sent to discussion {}", discussion_id);
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        Err(format!("Olvid HTTP {}: {}", status, body))
    }
}

/// Test connectivity to the Olvid daemon.
pub async fn test_connection(daemon_url: &str, client_key: &str) -> Result<String, String> {
    let url = format!("{}/v1/identity/get", daemon_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client.post(&url)
        .json(&serde_json::json!({ "client_key": client_key }))
        .send()
        .await
        .map_err(|e| format!("Olvid daemon unreachable: {e}"))?;

    if resp.status().is_success() {
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        let display_name = data["identity"]["display_name"].as_str().unwrap_or("Olvid Bot");
        Ok(format!("Connecté: {}", display_name))
    } else {
        Err(format!("Olvid HTTP {}", resp.status()))
    }
}

/// List available discussions (for config UI — helps user find discussion_id).
pub async fn list_discussions(daemon_url: &str, client_key: &str) -> Result<Vec<(String, String)>, String> {
    let url = format!("{}/v1/discussion/list", daemon_url.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client.post(&url)
        .json(&serde_json::json!({ "client_key": client_key }))
        .send()
        .await
        .map_err(|e| format!("Olvid daemon unreachable: {e}"))?;

    if resp.status().is_success() {
        let data: serde_json::Value = resp.json().await.unwrap_or_default();
        let discussions = data["discussions"].as_array()
            .map(|arr| arr.iter().filter_map(|d| {
                let id = d["id"].as_str()?.to_string();
                let title = d["title"].as_str().unwrap_or("Sans titre").to_string();
                Some((id, title))
            }).collect())
            .unwrap_or_default();
        Ok(discussions)
    } else {
        Err(format!("Olvid HTTP {}", resp.status()))
    }
}
