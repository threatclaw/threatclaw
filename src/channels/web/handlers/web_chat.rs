//! Web chat endpoints for the dashboard conversational pane.
//!
//! Option A (non-streaming): each POST /api/tc/chat is a synchronous round-trip.
//! The user's message is persisted, the L0 command interpreter runs to
//! completion, and the assistant's reply is persisted before returning — the
//! same pipeline Slack/Mattermost/Discord already use, just behind HTTP.
//!
//! Streaming (Option B from roadmap §3.6) can swap this handler for an SSE
//! variant without changing the schema: V47 already carries
//! `status='streaming'`, `tool_calls`, `citations`.
//!
//! Channel label `web` on conversations isolates dashboard threads from the
//! messenger-backed conversations already in the table.
//!
//! Identity: this endpoint trusts the dashboard's session auth upstream (same
//! middleware as /api/tc/incidents). `user_id` in the payload is derived from
//! the authenticated principal and is also what `list_conversations_with_preview`
//! filters on.

use axum::{
    extract::{Json, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::channels::web::server::GatewayState;

const WEB_CHANNEL: &str = "web";
const MAX_TITLE_LEN: usize = 60;
const DEFAULT_PAGE_LIMIT: i64 = 50;
const MAX_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct ChatRequest {
    pub message: String,
    #[serde(default)]
    pub conversation_id: Option<Uuid>,
    #[serde(default = "default_user")]
    pub user_id: String,
}

fn default_user() -> String {
    "rssi".to_string()
}

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub conversation_id: Uuid,
    pub user_message_id: Uuid,
    pub assistant_message_id: Uuid,
    pub content: String,
    pub tool_calls: Option<Value>,
    pub success: bool,
}

/// POST /api/tc/chat — run one turn of the L0 bot and persist both sides.
pub async fn chat_send_handler(
    State(state): State<Arc<GatewayState>>,
    Json(req): Json<ChatRequest>,
) -> impl IntoResponse {
    let trimmed = req.message.trim();
    if trimmed.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "message cannot be empty" })),
        )
            .into_response();
    }
    if trimmed.len() > 4000 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": "message exceeds 4000 characters" })),
        )
            .into_response();
    }

    let store = match state.store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not connected" })),
            )
                .into_response();
        }
    };

    let conv_id = req.conversation_id.unwrap_or_else(Uuid::new_v4);
    let created = match store
        .ensure_conversation(conv_id, WEB_CHANNEL, &req.user_id, None)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("CHAT: ensure_conversation failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not create conversation" })),
            )
                .into_response();
        }
    };

    // Use the first user message as the conversation title so the sidebar has
    // something to show. Only set on first turn — subsequent calls on the same
    // conversation leave it alone.
    if created {
        let title = derive_title(trimmed);
        if let Err(e) = store
            .update_conversation_metadata_field(conv_id, "title", &Value::String(title))
            .await
        {
            tracing::warn!("CHAT: could not set conversation title: {e}");
        }
    }

    let user_msg_id = match store
        .add_conversation_message(conv_id, "user", trimmed)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("CHAT: add_conversation_message(user) failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not persist user message" })),
            )
                .into_response();
        }
    };

    let llm_config =
        crate::agent::llm_router::LlmRouterConfig::from_db_settings(store.as_ref()).await;
    let cmd = crate::agent::command_interpreter::parse_command(trimmed, &llm_config).await;
    let result =
        crate::agent::command_interpreter::execute_command(&cmd, store.as_ref(), &llm_config).await;

    let assistant_msg_id = match store
        .add_conversation_message(conv_id, "assistant", &result.message)
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("CHAT: add_conversation_message(assistant) failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not persist assistant message" })),
            )
                .into_response();
        }
    };

    tracing::info!(
        "CHAT: web conv={} user={} action={} confidence={:.2}",
        conv_id,
        req.user_id,
        cmd.action,
        cmd.confidence
    );

    let response = ChatResponse {
        conversation_id: conv_id,
        user_message_id: user_msg_id,
        assistant_message_id: assistant_msg_id,
        content: result.message,
        tool_calls: result.data,
        success: result.success,
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
        .into_response()
}

/// GET /api/tc/conversations?user_id=X&limit=50 — list web conversations (preview only).
pub async fn conversations_list_handler(
    State(state): State<Arc<GatewayState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let store = match state.store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not connected" })),
            )
                .into_response();
        }
    };

    let user_id = params.get("user_id").map(String::as_str).unwrap_or("rssi");
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .map(|n| n.clamp(1, MAX_PAGE_LIMIT))
        .unwrap_or(DEFAULT_PAGE_LIMIT);

    match store
        .list_conversations_with_preview(user_id, WEB_CHANNEL, limit)
        .await
    {
        Ok(items) => {
            let items_json: Vec<Value> = items
                .into_iter()
                .map(|c| {
                    json!({
                        "id": c.id,
                        "title": c.title,
                        "message_count": c.message_count,
                        "started_at": c.started_at,
                        "last_activity": c.last_activity,
                        "channel": c.channel,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "conversations": items_json }))).into_response()
        }
        Err(e) => {
            tracing::error!("CHAT: list_conversations_with_preview failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not list conversations" })),
            )
                .into_response()
        }
    }
}

/// GET /api/tc/conversations/{id}/messages?limit=50 — paginated history (oldest first).
pub async fn conversation_messages_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<Uuid>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let store = match state.store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not connected" })),
            )
                .into_response();
        }
    };

    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .map(|n| n.clamp(1, MAX_PAGE_LIMIT))
        .unwrap_or(DEFAULT_PAGE_LIMIT);

    let before = params
        .get("before")
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    match store
        .list_conversation_messages_paginated(id, before, limit)
        .await
    {
        Ok((mut msgs, has_more)) => {
            msgs.reverse();
            let msgs_json: Vec<Value> = msgs
                .into_iter()
                .map(|m| {
                    json!({
                        "id": m.id,
                        "role": m.role,
                        "content": m.content,
                        "created_at": m.created_at,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "messages": msgs_json, "has_more": has_more })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("CHAT: list_conversation_messages_paginated failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not list messages" })),
            )
                .into_response()
        }
    }
}

/// DELETE /api/tc/conversations/{id} — soft-delete via metadata (sets deleted_at).
pub async fn conversation_delete_handler(
    State(state): State<Arc<GatewayState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let store = match state.store.as_ref() {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "database not connected" })),
            )
                .into_response();
        }
    };

    let stamp = chrono::Utc::now().to_rfc3339();
    match store
        .update_conversation_metadata_field(id, "deleted_at", &Value::String(stamp))
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({ "ok": true }))).into_response(),
        Err(e) => {
            tracing::error!("CHAT: soft-delete failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "could not delete conversation" })),
            )
                .into_response()
        }
    }
}

fn derive_title(message: &str) -> String {
    let first_line = message.lines().next().unwrap_or("").trim();
    let mut chars: Vec<char> = first_line.chars().collect();
    if chars.len() > MAX_TITLE_LEN {
        chars.truncate(MAX_TITLE_LEN);
        let mut out: String = chars.into_iter().collect();
        out.push('…');
        out
    } else {
        chars.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_title_preserves_short_message() {
        assert_eq!(derive_title("Status"), "Status");
        assert_eq!(
            derive_title("Quels incidents ce matin ?"),
            "Quels incidents ce matin ?"
        );
    }

    #[test]
    fn derive_title_truncates_with_ellipsis() {
        let long = "a".repeat(100);
        let title = derive_title(&long);
        assert_eq!(title.chars().count(), MAX_TITLE_LEN + 1);
        assert!(title.ends_with('…'));
    }

    #[test]
    fn derive_title_keeps_only_first_line() {
        let msg = "First line\nSecond line\nThird";
        assert_eq!(derive_title(msg), "First line");
    }

    #[test]
    fn derive_title_handles_multibyte_safely() {
        let emoji_heavy = "🔥🔥🔥 ".repeat(30);
        // Must not panic on char boundary — assert that it produces a valid String.
        let title = derive_title(&emoji_heavy);
        assert!(title.chars().count() <= MAX_TITLE_LEN + 1);
    }
}
