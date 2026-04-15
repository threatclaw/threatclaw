// See ADR-043: Incoming message handlers for multi-channel conversational bot.
// Each channel that supports receiving messages has a webhook endpoint here.
// Messages are forwarded to the channel-agnostic command handler.

use crate::channels::web::server::GatewayState;
use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// POST /api/tc/channel/slack/incoming — Slack Events API / slash commands
pub async fn slack_incoming_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Slack URL verification challenge
    if let Some(challenge) = body.get("challenge").and_then(|c| c.as_str()) {
        return (StatusCode::OK, Json(json!({ "challenge": challenge }))).into_response();
    }

    // Slack event (message)
    let event = &body["event"];
    let event_type = event["type"].as_str().unwrap_or("");
    if event_type != "message" && event_type != "app_mention" {
        return (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    }

    // Ignore bot messages (prevent loops)
    if event.get("bot_id").is_some() || event["subtype"].as_str() == Some("bot_message") {
        return (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    }

    let text = event["text"].as_str().unwrap_or("");
    let user = event["user"].as_str().unwrap_or("unknown");
    let channel_id = event["channel"].as_str().unwrap_or("");

    if text.is_empty() {
        return (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    }

    tracing::info!(
        "CHANNEL_IN: Slack message from {} in {}: {}",
        user,
        channel_id,
        &text[..text.len().min(50)]
    );

    // Forward to command handler
    let response = process_incoming_message(state.clone(), text, "slack", user).await;

    // Reply in Slack
    if let Some(ref store) = state.store {
        let _ = reply_to_slack(store.as_ref(), channel_id, &response).await;
    }

    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

/// POST /api/tc/channel/mattermost/incoming — Mattermost outgoing webhook
pub async fn mattermost_incoming_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = body["text"].as_str().unwrap_or("");
    let user = body["user_name"].as_str().unwrap_or("unknown");
    let trigger = body["trigger_word"].as_str().unwrap_or("");

    // Remove trigger word from message
    let clean_text = text.strip_prefix(trigger).unwrap_or(text).trim();
    if clean_text.is_empty() {
        return Json(json!({ "text": "Envoyez une commande (ex: status, scan, findings)" }));
    }

    tracing::info!(
        "CHANNEL_IN: Mattermost message from {}: {}",
        user,
        &clean_text[..clean_text.len().min(50)]
    );

    let response = process_incoming_message(state, clean_text, "mattermost", user).await;

    // Mattermost expects a JSON response with "text"
    Json(json!({ "text": response, "response_type": "comment" }))
}

/// POST /api/tc/channel/discord/incoming — Discord interactions endpoint
pub async fn discord_incoming_handler(
    State(state): State<Arc<GatewayState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let interaction_type = body["type"].as_u64().unwrap_or(0);

    // Discord ping verification
    if interaction_type == 1 {
        return (StatusCode::OK, Json(json!({ "type": 1 }))).into_response();
    }

    // Slash command
    if interaction_type == 2 {
        let text = body["data"]["options"][0]["value"].as_str().unwrap_or("");
        let user = body["member"]["user"]["username"]
            .as_str()
            .unwrap_or("unknown");

        tracing::info!("CHANNEL_IN: Discord command from {}: {}", user, text);

        let response = process_incoming_message(state, text, "discord", user).await;

        return (
            StatusCode::OK,
            Json(json!({
                "type": 4,
                "data": { "content": response }
            })),
        )
            .into_response();
    }

    (StatusCode::OK, Json(json!({ "type": 1 }))).into_response()
}

/// POST /api/tc/channel/generic/incoming — Generic webhook (Signal, WhatsApp, custom)
pub async fn generic_incoming_handler(
    State(state): State<Arc<GatewayState>>,
    Path(channel_name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = body["message"]
        .as_str()
        .or(body["text"].as_str())
        .or(body["content"].as_str())
        .unwrap_or("");
    let user = body["from"]
        .as_str()
        .or(body["sender"].as_str())
        .or(body["user"].as_str())
        .unwrap_or("unknown");

    if text.is_empty() {
        return Json(json!({ "error": "No message found in body" }));
    }

    tracing::info!(
        "CHANNEL_IN: {} message from {}: {}",
        channel_name,
        user,
        &text[..text.len().min(50)]
    );

    let response = process_incoming_message(state, text, &channel_name, user).await;

    Json(json!({ "response": response, "channel": channel_name }))
}

/// Process any incoming message through the command pipeline.
async fn process_incoming_message(
    state: Arc<GatewayState>,
    message: &str,
    channel: &str,
    user: &str,
) -> String {
    let store = match state.store.as_ref() {
        Some(s) => s,
        None => return "ThreatClaw non connecte a la base de donnees".into(),
    };

    let llm_config =
        crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref()).await;

    // Parse command via LLM
    let cmd = crate::agent::command_interpreter::parse_command(message, &llm_config).await;

    // Execute
    let result =
        crate::agent::command_interpreter::execute_command(&cmd, store.as_ref(), &llm_config).await;

    let response_text = &result.message;

    tracing::info!(
        "CHANNEL_OUT: {} → {}: {}",
        channel,
        user,
        &response_text[..response_text.len().min(80)]
    );

    response_text.to_string()
}

/// Reply to a Slack message.
async fn reply_to_slack(
    store: &dyn crate::db::Database,
    channel_id: &str,
    text: &str,
) -> Result<(), String> {
    let channels = store
        .get_setting("_system", "tc_config_channels")
        .await
        .ok()
        .flatten()
        .ok_or("No channels config")?;
    let token = channels["slack"]["botToken"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Slack token not found")?;

    reqwest::Client::new()
        .post("https://slack.com/api/chat.postMessage")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "channel": channel_id, "text": text }))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
