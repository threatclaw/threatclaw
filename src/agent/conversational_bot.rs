//! Conversational Bot — listens to channels and executes RSSI commands.
//!
//! Runs as a background task, polling Telegram (and other channels)
//! for incoming messages. Parses commands via LLM and executes them.
//!
//! Architecture:
//!   RSSI sends message → poll → parse (L1) → confirm → execute → respond
//!
//! Supported channels: Telegram (polling), Slack (webhook), any future channel.
//! Commands are channel-agnostic — the interpreter is shared.

use std::sync::Arc;
use std::collections::HashMap;

use serde_json::json;
use tokio::sync::Mutex;

use crate::agent::command_interpreter::{
    self, ParsedCommand, ExecutionType, PendingConfirmation,
    format_for_telegram, format_confirmation_request,
};
use crate::agent::llm_router::LlmRouterConfig;
use crate::db::Database;

/// A conversation message (for context memory).
#[derive(Debug, Clone)]
struct ConvMessage {
    role: String,      // "user" or "assistant"
    content: String,
    timestamp: chrono::DateTime<chrono::Utc>,
}

/// Conversation history per chat (keeps last N exchanges).
const MAX_HISTORY: usize = 10;

/// State for the conversational bot.
struct BotState {
    /// Pending confirmations per chat_id.
    pending: HashMap<String, PendingConfirmation>,
    /// Conversation history per chat_id (for context).
    history: HashMap<String, Vec<ConvMessage>>,
    /// Last mentioned target per chat_id (for pronoun resolution).
    last_target: HashMap<String, String>,
    /// Last action per chat_id (for follow-up suggestions).
    last_action: HashMap<String, String>,
    /// Last processed Telegram update_id (for offset).
    last_update_id: i64,
}

/// Start the Telegram polling bot as a background task.
/// Polls every 5 seconds for new messages.
pub fn spawn_telegram_bot(
    store: Arc<dyn Database>,
    poll_interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("CONV_BOT: Telegram polling bot starting...");

        let state = Arc::new(Mutex::new(BotState {
            pending: HashMap::new(),
            history: HashMap::new(),
            last_target: HashMap::new(),
            last_action: HashMap::new(),
            last_update_id: 0,
        }));

        // Wait for backend to be ready
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let mut had_messages;
        loop {
            had_messages = false;

            // Get Telegram token and chat_id from config
            let (token, allowed_chat_id) = match get_telegram_config(&store).await {
                Some(c) => c,
                None => continue, // Not configured, skip
            };

            // Poll for updates
            let offset = {
                let s = state.lock().await;
                s.last_update_id + 1
            };

            let updates = match poll_telegram(&token, offset).await {
                Ok(u) => u,
                Err(e) => {
                    tracing::debug!("CONV_BOT: Poll failed: {e}");
                    continue;
                }
            };

            for update in updates {
                let update_id = update["update_id"].as_i64().unwrap_or(0);

                // Update offset
                {
                    let mut s = state.lock().await;
                    if update_id > s.last_update_id {
                        s.last_update_id = update_id;
                    }
                }

                // Handle callback_query (HITL button clicks)
                if let Some(callback) = update.get("callback_query") {
                    let callback_id = callback["id"].as_str().unwrap_or("");
                    let data = callback["data"].as_str().unwrap_or("");
                    let cb_chat_id = callback["message"]["chat"]["id"].as_i64().unwrap_or(0).to_string();
                    let cb_message_id = callback["message"]["message_id"].as_i64().unwrap_or(0);
                    let cb_from = callback["from"]["username"].as_str().unwrap_or("unknown");

                    tracing::info!("CONV_BOT: Callback query from @{}: {}", cb_from, data);

                    // Parse callback data: "hitl_approve_{nonce}" or "hitl_reject_{nonce}"
                    if data.starts_with("hitl_") {
                        let parts: Vec<&str> = data.splitn(3, '_').collect();
                        if parts.len() >= 3 {
                            let action = parts[1]; // "approve" or "reject"
                            let nonce = parts[2];
                            let approved = action == "approve";

                            // Answer the callback (remove spinning indicator)
                            let _ = reqwest::Client::new()
                                .post(format!("https://api.telegram.org/bot{token}/answerCallbackQuery"))
                                .json(&json!({ "callback_query_id": callback_id, "text": if approved { "Approuvé" } else { "Rejeté" } }))
                                .send().await;

                            // TODO: verify nonce via shared NonceManager and execute
                            // For now, send confirmation message
                            let status_text = if approved {
                                format!("Action approuvée par @{cb_from}. Exécution en cours...")
                            } else {
                                format!("Action rejetée par @{cb_from}.")
                            };

                            // Edit the original message to show the result
                            let _ = reqwest::Client::new()
                                .post(format!("https://api.telegram.org/bot{token}/editMessageText"))
                                .json(&json!({
                                    "chat_id": cb_chat_id,
                                    "message_id": cb_message_id,
                                    "text": status_text,
                                    "parse_mode": "Markdown",
                                }))
                                .send().await;
                        }
                    }
                    continue;
                }

                let message = &update["message"];
                let text = message["text"].as_str().unwrap_or("");
                let chat_id = message["chat"]["id"].as_i64().unwrap_or(0).to_string();
                let from = message["from"]["username"].as_str().unwrap_or("unknown");

                if text.is_empty() { continue; }

                // Security: only process messages from allowed chat
                if !allowed_chat_id.is_empty() && chat_id != allowed_chat_id {
                    tracing::warn!("CONV_BOT: Ignoring message from unauthorized chat_id={chat_id} (expected {allowed_chat_id})");
                    continue;
                }

                had_messages = true;

                // Check if system is paused
                if let Ok(Some(paused)) = store.get_setting("_system", "tc_paused").await {
                    if paused.as_bool() == Some(true) {
                        send_telegram(&token, &chat_id, "ThreatClaw est en pause. Reprenez depuis le dashboard.").await;
                        continue;
                    }
                }

                tracing::info!("CONV_BOT: Message from @{from} (chat={chat_id}): {text}");

                // Check if this is a confirmation response
                let is_confirmation = {
                    let s = state.lock().await;
                    s.pending.contains_key(&chat_id)
                };

                if is_confirmation {
                    handle_confirmation(&token, &chat_id, text, &store, &state).await;
                } else {
                    handle_new_command(&token, &chat_id, text, &store, &state).await;
                }
            }
            // end of for update in updates

            // Only sleep between polls if there were no messages (idle)
            // When there are messages, poll again immediately for responsiveness
            if !had_messages {
                tokio::time::sleep(poll_interval).await;
            }
        }
        // end of loop
    })
}

/// Get Telegram config from DB.
async fn get_telegram_config(store: &Arc<dyn Database>) -> Option<(String, String)> {
    // Token from env or DB
    let token = if let Ok(t) = std::env::var("TELEGRAM_BOT_TOKEN") {
        if !t.is_empty() { t } else { return None; }
    } else if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        channels["telegram"]["botToken"].as_str().filter(|t| !t.is_empty())?.to_string()
    } else {
        return None;
    };

    // Allowed chat ID
    let chat_id = if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        channels["telegram"]["chatId"].as_str().unwrap_or("").trim().to_string()
    } else {
        String::new()
    };

    // Check if channel is enabled
    if let Ok(Some(channels)) = store.get_setting("_system", "tc_config_channels").await {
        if channels["telegram"]["enabled"].as_bool() != Some(true) {
            return None;
        }
    }

    Some((token, chat_id))
}

/// Poll Telegram for new updates.
async fn poll_telegram(token: &str, offset: i64) -> Result<Vec<serde_json::Value>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client.get(format!("https://api.telegram.org/bot{token}/getUpdates"))
        .query(&[
            ("offset", offset.to_string()),
            ("timeout", "10".to_string()),
            ("allowed_updates", "[\"message\",\"callback_query\"]".to_string()),
        ])
        .send().await
        .map_err(|e| e.to_string())?;

    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    if data["ok"].as_bool() != Some(true) {
        return Err(format!("Telegram API error: {}", data["description"].as_str().unwrap_or("unknown")));
    }

    Ok(data["result"].as_array().cloned().unwrap_or_default())
}

/// L0 Conversational Engine — orchestrates tool calling and natural response.
/// Supports native (Ollama tools API) and prompt-based (JSON in prompt) modes.
/// Works with local Ollama models or cloud APIs.
async fn call_l0_conversation(
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
    system_prompt: &str,
    user_message: &str,
    store: &Arc<dyn Database>,
    history_context: &str,
) -> Option<String> {
    use crate::agent::llm_router::{L0Source, ToolCallMode};
    use crate::agent::tool_calling;

    let l0 = &llm_config.conversational;

    // Determine source and model
    let (use_cloud, model, backend, api_key, base_url) = match &l0.source {
        L0Source::Cloud => {
            (true, l0.cloud_model.clone(), l0.cloud_backend.clone(), l0.cloud_api_key.clone(), l0.cloud_base_url.clone())
        }
        L0Source::Local => {
            (false, l0.local_model.clone(), String::new(), String::new(), None)
        }
        L0Source::Disabled => {
            // Fallback: use old behavior (try cloud L3, then local models)
            return call_llm_fallback(llm_config, system_prompt, user_message).await;
        }
    };

    let tool_mode = l0.detect_tool_call_mode();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120)) // 120s to handle first model load on CPU
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build().ok()?;

    // Build system prompt with tool descriptions (for prompt-based mode)
    let full_system = if tool_mode == ToolCallMode::PromptBased {
        format!("{}\n\n{}\n\nConversation récente:\n{}", system_prompt, tool_calling::tools_for_prompt(), history_context)
    } else {
        format!("{}\n\nConversation récente:\n{}", system_prompt, history_context)
    };

    // ── Step 1: First LLM call (may produce a tool call or direct response) ──
    let first_response = if use_cloud {
        call_cloud_api(&client, &backend, &model, &api_key, &base_url, &full_system, user_message, tool_mode).await
    } else {
        call_ollama_l0(&client, &l0.ollama_url, &model, &full_system, user_message, tool_mode).await
    };

    let (content, tool_calls) = match first_response {
        Some(r) => r,
        None => return call_llm_fallback(llm_config, system_prompt, user_message).await,
    };

    // ── Step 2: If tool call detected, execute it and call LLM again with results ──
    let tool_call = if !tool_calls.is_empty() {
        // Native tool call from Ollama/cloud
        Some(tool_calls[0].clone())
    } else if tool_mode == ToolCallMode::PromptBased {
        // Try to parse tool call from text response
        tool_calling::parse_tool_call_from_text(&content)
    } else {
        None
    };

    if let Some(tc) = tool_call {
        tracing::info!("CONV_BOT L0: Tool call → {}({:?})", tc.name, tc.arguments);
        let tool_result = tool_calling::execute_tool(&tc, store).await;
        let tool_result_json = serde_json::to_string(&tool_result.data).unwrap_or_default();
        tracing::info!("CONV_BOT L0: Tool result ({} chars)", tool_result_json.len());

        // ── Step 3: Second LLM call with tool results injected ──
        let followup_system = format!(
            "{}\n\nRéponds en français naturel et concis basé sur les données réelles ci-dessous. \
             Ne répète pas les données brutes, synthétise-les pour le RSSI.",
            system_prompt
        );
        let followup_message = format!(
            "Question: {}\n\nRésultat de {} :\n{}",
            user_message, tc.name, tool_result_json
        );

        let second_response = if use_cloud {
            call_cloud_api(&client, &backend, &model, &api_key, &base_url, &followup_system, &followup_message, ToolCallMode::None).await
        } else {
            call_ollama_l0(&client, &l0.ollama_url, &model, &followup_system, &followup_message, ToolCallMode::None).await
        };

        if let Some((text, _)) = second_response {
            let clean = clean_llm_response(&text);
            if !clean.is_empty() {
                return Some(clean);
            }
        }

        // If second call fails, format tool results directly
        return Some(format_tool_result_as_text(&tc.name, &tool_result.data));
    }

    // No tool call — direct conversational response
    let clean = clean_llm_response(&content);
    if clean.is_empty() { None } else { Some(clean) }
}

/// Call Ollama local model for L0 conversation.
async fn call_ollama_l0(
    client: &reqwest::Client,
    ollama_url: &str,
    model: &str,
    system_prompt: &str,
    user_message: &str,
    tool_mode: crate::agent::llm_router::ToolCallMode,
) -> Option<(String, Vec<crate::agent::tool_calling::ToolCall>)> {
    use crate::agent::llm_router::ToolCallMode;

    let mut body = json!({
        "model": model,
        "messages": [
            { "role": "system", "content": format!("{} /no_think", system_prompt) },
            { "role": "user", "content": user_message }
        ],
        "stream": false,
        "options": { "temperature": 0.7, "num_predict": 500 }
    });

    // Add tools for native mode
    if tool_mode == ToolCallMode::Native {
        body["tools"] = crate::agent::tool_calling::tools_for_ollama();
    }

    match client.post(format!("{}/api/chat", ollama_url)).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let content = data["message"]["content"].as_str()
                    .or_else(|| data["response"].as_str())
                    .unwrap_or("").to_string();

                // Extract native tool calls
                let mut tool_calls = Vec::new();
                if let Some(calls) = data["message"]["tool_calls"].as_array() {
                    for call in calls {
                        if let Some(name) = call["function"]["name"].as_str() {
                            let args = call["function"]["arguments"].clone();
                            tool_calls.push(crate::agent::tool_calling::ToolCall {
                                name: name.to_string(),
                                arguments: args,
                            });
                        }
                    }
                }

                let tok_count = data["eval_count"].as_u64().unwrap_or(0);
                let duration = data["eval_duration"].as_f64().unwrap_or(1.0) / 1e9;
                tracing::info!(
                    "CONV_BOT L0: {} responded ({} chars, {} tok, {:.1} tok/s, {} tool_calls)",
                    model, content.len(), tok_count,
                    tok_count as f64 / duration.max(0.001),
                    tool_calls.len()
                );

                Some((content, tool_calls))
            } else {
                None
            }
        }
        Ok(resp) => {
            tracing::warn!("CONV_BOT L0: Ollama {} error: HTTP {}", model, resp.status());
            None
        }
        Err(e) => {
            tracing::warn!("CONV_BOT L0: Ollama {} failed: {}", model, e);
            None
        }
    }
}

/// Call cloud API for L0 conversation.
async fn call_cloud_api(
    client: &reqwest::Client,
    backend: &str,
    model: &str,
    api_key: &str,
    base_url: &Option<String>,
    system_prompt: &str,
    user_message: &str,
    tool_mode: crate::agent::llm_router::ToolCallMode,
) -> Option<(String, Vec<crate::agent::tool_calling::ToolCall>)> {
    use crate::agent::llm_router::ToolCallMode;

    let api_url = match backend {
        "mistral" => "https://api.mistral.ai/v1/chat/completions".to_string(),
        "anthropic" => "https://api.anthropic.com/v1/messages".to_string(),
        _ => base_url.clone().unwrap_or("https://api.openai.com/v1/chat/completions".into()),
    };

    let mut body = if backend == "anthropic" {
        json!({
            "model": model,
            "max_tokens": 500,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}]
        })
    } else {
        json!({
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 500,
            "temperature": 0.7
        })
    };

    // Add tools for native mode (non-Anthropic)
    if tool_mode == ToolCallMode::Native && backend != "anthropic" {
        body["tools"] = crate::agent::tool_calling::tools_for_ollama();
    }

    let mut req = client.post(&api_url).json(&body);
    if backend == "anthropic" {
        req = req.header("x-api-key", api_key)
                 .header("anthropic-version", "2023-06-01");
    } else {
        req = req.header("Authorization", format!("Bearer {}", api_key));
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let content = if backend == "anthropic" {
                    data["content"][0]["text"].as_str().unwrap_or("").to_string()
                } else {
                    data["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string()
                };

                // Extract native tool calls (OpenAI/Mistral format)
                let mut tool_calls = Vec::new();
                if let Some(calls) = data["choices"][0]["message"]["tool_calls"].as_array() {
                    for call in calls {
                        if let Some(name) = call["function"]["name"].as_str() {
                            let args_str = call["function"]["arguments"].as_str().unwrap_or("{}");
                            let args: serde_json::Value = serde_json::from_str(args_str).unwrap_or(json!({}));
                            tool_calls.push(crate::agent::tool_calling::ToolCall {
                                name: name.to_string(),
                                arguments: args,
                            });
                        }
                    }
                }

                tracing::info!("CONV_BOT L0: Cloud {} responded ({} chars, {} tool_calls)", backend, content.len(), tool_calls.len());
                Some((content, tool_calls))
            } else {
                None
            }
        }
        Ok(resp) => {
            tracing::warn!("CONV_BOT L0: Cloud {} error: HTTP {}", backend, resp.status());
            None
        }
        Err(e) => {
            tracing::warn!("CONV_BOT L0: Cloud {} failed: {}", backend, e);
            None
        }
    }
}

/// Fallback: old behavior when L0 is disabled.
async fn call_llm_fallback(
    llm_config: &crate::agent::llm_router::LlmRouterConfig,
    system_prompt: &str,
    user_message: &str,
) -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build().ok()?;

    // Try Cloud L3 if configured
    if let Some(ref cloud) = llm_config.cloud {
        if !cloud.api_key.is_empty() {
            let result = call_cloud_api(
                &client, &cloud.backend, &cloud.model, &cloud.api_key,
                &cloud.base_url, system_prompt, user_message,
                crate::agent::llm_router::ToolCallMode::None,
            ).await;
            if let Some((text, _)) = result {
                let clean = clean_llm_response(&text);
                if !clean.is_empty() { return Some(clean); }
            }
        }
    }

    // Fallback local models
    let base_url = &llm_config.primary.base_url;
    let models = ["threatclaw-l3", "threatclaw-l1", &llm_config.primary.model];
    for model in &models {
        let body = json!({
            "model": model,
            "messages": [
                { "role": "system", "content": format!("{} /no_think", system_prompt) },
                { "role": "user", "content": user_message }
            ],
            "stream": false,
            "options": { "temperature": 0.7, "num_predict": 500 }
        });
        match client.post(format!("{}/api/chat", base_url)).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let content = data["message"]["content"].as_str()
                        .or_else(|| data["response"].as_str())
                        .unwrap_or("");
                    let clean = clean_llm_response(content);
                    if !clean.is_empty() {
                        tracing::info!("CONV_BOT: Fallback {} responded ({} chars)", model, clean.len());
                        return Some(clean);
                    }
                }
            }
            _ => continue,
        }
    }
    None
}

/// Clean LLM response: remove think tags, JSON wrapping, etc.
fn clean_llm_response(text: &str) -> String {
    let trimmed = text.trim();

    // Remove <think>...</think> blocks
    let clean = if let Some(pos) = trimmed.find("</think>") {
        trimmed[pos + 8..].trim()
    } else {
        trimmed
    };

    // If response is JSON, try to extract text content
    if clean.starts_with('{') || clean.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(clean) {
            fn extract_text(v: &serde_json::Value) -> Option<String> {
                match v {
                    serde_json::Value::String(s) if s.len() > 20 => Some(s.clone()),
                    serde_json::Value::Object(map) => {
                        for key in &["greeting", "message", "response", "text", "résumé", "summary", "content", "answer"] {
                            if let Some(val) = map.get(*key) {
                                if let Some(s) = val.as_str() {
                                    if s.len() > 10 { return Some(s.to_string()); }
                                }
                                if let Some(s) = extract_text(val) { return Some(s); }
                            }
                        }
                        for val in map.values() {
                            if let Some(s) = extract_text(val) { return Some(s); }
                        }
                        None
                    }
                    serde_json::Value::Array(arr) => {
                        for val in arr { if let Some(s) = extract_text(val) { return Some(s); } }
                        None
                    }
                    _ => None,
                }
            }
            if let Some(extracted) = extract_text(&v) {
                return extracted;
            }
        }
    }

    clean.to_string()
}

/// Format tool result as human-readable text (fallback when LLM second call fails).
fn format_tool_result_as_text(tool_name: &str, data: &serde_json::Value) -> String {
    match tool_name {
        "get_security_status" => {
            format!("Score sécurité : *{:.0}/100* — {}\nAlertes : {} · Findings : {} · Assets : {}",
                data["score"].as_f64().unwrap_or(0.0),
                data["label"].as_str().unwrap_or("?"),
                data["alerts_active"].as_i64().unwrap_or(0),
                data["findings_open"].as_i64().unwrap_or(0),
                data["assets_monitored"].as_i64().unwrap_or(0))
        }
        "get_recent_alerts" => {
            let mut lines = vec![format!("{} alertes récentes :", data["total"].as_i64().unwrap_or(0))];
            if let Some(alerts) = data["alerts"].as_array() {
                for a in alerts.iter().take(5) {
                    lines.push(format!("• [{}] {} — {} ({})",
                        a["level"].as_str().unwrap_or("?"),
                        a["title"].as_str().unwrap_or("?"),
                        a["hostname"].as_str().unwrap_or("?"),
                        a["timestamp"].as_str().unwrap_or("?")));
                }
            }
            lines.join("\n")
        }
        "get_recent_findings" => {
            let mut lines = vec![format!("{} findings ouverts :", data["total"].as_i64().unwrap_or(0))];
            if let Some(findings) = data["findings"].as_array() {
                for f in findings.iter().take(5) {
                    lines.push(format!("• [{}] {} — {}",
                        f["severity"].as_str().unwrap_or("?"),
                        f["title"].as_str().unwrap_or("?"),
                        f["asset"].as_str().unwrap_or("?")));
                }
            }
            lines.join("\n")
        }
        _ => serde_json::to_string_pretty(data).unwrap_or_else(|_| "Données disponibles.".into()),
    }
}

async fn send_telegram(token: &str, chat_id: &str, text: &str) {
    let client = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Truncate for Telegram limit (4096 chars)
    let text = if text.len() > 4000 {
        format!("{}...", &text[..4000])
    } else {
        text.to_string()
    };

    let _ = client.post(format!("https://api.telegram.org/bot{token}/sendMessage"))
        .json(&json!({ "chat_id": chat_id, "text": text, "parse_mode": "Markdown" }))
        .send().await;
}

/// Handle a new command (not a confirmation).
async fn handle_new_command(
    token: &str,
    chat_id: &str,
    text: &str,
    store: &Arc<dyn Database>,
    state: &Arc<Mutex<BotState>>,
) {
    // Record user message in history
    {
        let mut s = state.lock().await;
        let history = s.history.entry(chat_id.to_string()).or_default();
        history.push(ConvMessage {
            role: "user".into(),
            content: text.to_string(),
            timestamp: chrono::Utc::now(),
        });
        // Trim to max history
        if history.len() > MAX_HISTORY * 2 {
            *history = history.split_off(history.len() - MAX_HISTORY * 2);
        }
    }

    // Resolve pronouns: "bloque la", "scanne le", "vérifie la" → use last_target
    let resolved_text = {
        let s = state.lock().await;
        resolve_pronouns(text, s.last_target.get(chat_id), s.last_action.get(chat_id))
    };

    // Build conversation context for LLM
    let context = {
        let s = state.lock().await;
        build_conversation_context(s.history.get(chat_id), s.last_target.get(chat_id))
    };

    // Load LLM config
    let llm_config = LlmRouterConfig::from_db_settings(store.as_ref()).await;

    // Parse with context
    let mut cmd = command_interpreter::parse_command_with_context(&resolved_text, &context, &llm_config).await;

    // If no target found but we have a last_target, inject it
    if cmd.target.is_none() {
        let s = state.lock().await;
        if let Some(last) = s.last_target.get(chat_id) {
            // Only inject if the action typically needs a target
            if matches!(cmd.execution_type,
                ExecutionType::Skill { .. } | ExecutionType::Remediation { .. }) {
                cmd.target = Some(last.clone());
                cmd.summary = format!("{} (cible: {})", cmd.summary, last);
            }
        }
    }

    // Update last_target if command has a target
    if let Some(ref target) = cmd.target {
        let mut s = state.lock().await;
        s.last_target.insert(chat_id.to_string(), target.clone());
    }

    match &cmd.execution_type {
        ExecutionType::Unknown => {
            // No keyword matched → L0 conversational engine with tool calling
            let situation = store.get_setting("_system", "security_situation").await.ok().flatten();
            let score = situation.as_ref().and_then(|s| s["global_score"].as_f64()).unwrap_or(100.0);
            let alerts_count = store.count_alerts_filtered(None, Some("new")).await.unwrap_or(0);
            let findings_count = store.count_findings_filtered(None, Some("open"), None).await.unwrap_or(0);

            let history_ctx = {
                let s = state.lock().await;
                s.history.get(chat_id).map(|h| {
                    h.iter().rev().take(6).rev().map(|m| format!("{}: {}", m.role, m.content)).collect::<Vec<_>>().join("\n")
                }).unwrap_or_default()
            };

            let system_prompt = format!(
                "Tu es ThreatClaw, un agent cybersécurité pour PME. Réponds en français naturel, JAMAIS en JSON brut.\n\
                 Score sécurité actuel : {:.0}/100. {} alertes actives. {} vulnérabilités ouvertes.\n\
                 Tu vouvoies le RSSI. Sois concis (3-4 phrases max) mais précis.\n\
                 Si la question porte sur l'état de l'infrastructure, utilise les outils disponibles pour donner des données réelles.\n\
                 Ne jamais inventer de données — utilise uniquement ce que les outils retournent.",
                score, alerts_count, findings_count
            );

            let llm_response = call_l0_conversation(&llm_config, &system_prompt, text, store, &history_ctx).await;

            let response = match llm_response {
                Some(resp) => resp,
                None => {
                    format!(
                        "Score sécurité : *{:.0}/100*\n{} alertes · {} vulnérabilités\n\n\
                        Commandes : `status` · `alertes` · `findings` · `scan` · `playbook`",
                        score, alerts_count, findings_count
                    )
                }
            };

            send_telegram(token, chat_id, &response).await;
            record_history(state, chat_id, &response).await;
        }
        ExecutionType::Remediation { .. } => {
            // Need confirmation for remediation actions
            let confirm_msg = format_confirmation_request(&cmd);
            send_telegram(token, chat_id, &confirm_msg).await;
            record_history(state, chat_id, &confirm_msg).await;
            let mut s = state.lock().await;
            s.last_action.insert(chat_id.to_string(), cmd.action.clone());
            s.pending.insert(chat_id.to_string(), PendingConfirmation {
                command: cmd,
                channel: "telegram".into(),
                chat_id: chat_id.into(),
                created_at: chrono::Utc::now(),
            });
        }
        _ => {
            // Execute directly (queries, skills, instruct)
            send_telegram(token, chat_id, &format!("⏳ {}", cmd.summary)).await;
            let result = command_interpreter::execute_command(&cmd, store.as_ref(), &llm_config).await;

            // Build response with follow-up suggestion
            let response = format_for_telegram(&result);
            let suggestion = suggest_followup(&cmd, &result);
            let full_response = if let Some(sug) = &suggestion {
                format!("{}\n\n💡 _{}_", response, sug)
            } else {
                response.clone()
            };

            send_telegram(token, chat_id, &full_response).await;
            record_history(state, chat_id, &response).await;

            // Update state
            {
                let mut s = state.lock().await;
                s.last_action.insert(chat_id.to_string(), cmd.action.clone());
            }

            // Audit
            let audit_key = format!("conv_bot_{}_{}", cmd.action, chrono::Utc::now().timestamp());
            let _ = store.set_setting("_audit", &audit_key, &json!({
                "action": cmd.action, "target": cmd.target, "channel": "telegram",
                "success": result.success, "timestamp": chrono::Utc::now().to_rfc3339(),
            })).await;
        }
    }
}

/// Record a bot response in conversation history.
async fn record_history(state: &Arc<Mutex<BotState>>, chat_id: &str, content: &str) {
    let mut s = state.lock().await;
    let history = s.history.entry(chat_id.to_string()).or_default();
    history.push(ConvMessage {
        role: "assistant".into(),
        content: content.chars().take(300).collect(),
        timestamp: chrono::Utc::now(),
    });
}

/// Resolve pronouns using conversation context.
/// "bloque la" → "bloque 192.168.1.50" (if last target was 192.168.1.50)
fn resolve_pronouns(text: &str, last_target: Option<&String>, _last_action: Option<&String>) -> String {
    let lower = text.to_lowercase();
    let pronouns = ["la", "le", "l'", "cette ip", "cette cible", "ce serveur", "lui", "dessus"];

    if let Some(target) = last_target {
        for pronoun in &pronouns {
            // Check if text ends with or contains the pronoun as a reference
            if lower.ends_with(pronoun) || lower.contains(&format!(" {} ", pronoun)) || lower.contains(&format!(" {}", pronoun)) {
                let resolved = text.to_string().replace(pronoun, target);
                // Also try with capitalized
                let resolved = resolved.replace(&pronoun.chars().next().unwrap().to_uppercase().to_string(), target);
                tracing::debug!("CONV_BOT: Pronoun resolved '{}' → '{}'", text, resolved);
                return resolved;
            }
        }
    }

    text.to_string()
}

/// Build conversation context string for LLM prompt.
fn build_conversation_context(history: Option<&Vec<ConvMessage>>, last_target: Option<&String>) -> String {
    let mut ctx = String::new();

    if let Some(target) = last_target {
        ctx.push_str(&format!("Dernière cible mentionnée: {}\n", target));
    }

    if let Some(hist) = history {
        let recent: Vec<&ConvMessage> = hist.iter().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
        if !recent.is_empty() {
            ctx.push_str("Conversation récente:\n");
            for msg in recent {
                let role = if msg.role == "user" { "RSSI" } else { "Bot" };
                ctx.push_str(&format!("{}: {}\n", role, msg.content.chars().take(150).collect::<String>()));
            }
        }
    }

    ctx
}

/// Suggest a follow-up action based on what was just done.
fn suggest_followup(cmd: &ParsedCommand, result: &command_interpreter::CommandResult) -> Option<String> {
    if !result.success { return None; }

    match cmd.action.as_str() {
        "lookup_ip" => {
            if let Some(ref target) = cmd.target {
                Some(format!("Bloquer cette IP ? Tapez `bloque {}`", target))
            } else {
                None
            }
        }
        "scan_port" | "scan_vuln" => {
            Some("Générer un playbook pour les vulnérabilités trouvées ? Tapez `playbook`".into())
        }
        "findings" => {
            Some("Lancer une analyse ReAct ? Tapez `analyse`".into())
        }
        "alerts" => {
            Some("Voir les findings associés ? Tapez `findings`".into())
        }
        "block_ip" => {
            Some("Vérifier que le blocage est effectif ? Tapez `status`".into())
        }
        "react" => {
            Some("Générer un rapport ? Tapez `rapport`".into())
        }
        _ => None,
    }
}

/// Handle a confirmation response (oui/non).
async fn handle_confirmation(
    token: &str,
    chat_id: &str,
    text: &str,
    store: &Arc<dyn Database>,
    state: &Arc<Mutex<BotState>>,
) {
    let lower = text.to_lowercase().trim().to_string();
    let confirmed = lower == "oui" || lower == "ok" || lower == "go" || lower == "yes"
        || lower == "confirmer" || lower == "confirm" || lower == "y";
    let cancelled = lower == "non" || lower == "no" || lower == "annuler" || lower == "cancel" || lower == "n";

    if !confirmed && !cancelled {
        send_telegram(token, chat_id, "Répondez *oui* pour exécuter ou *non* pour annuler.").await;
        return;
    }

    let pending = {
        let mut s = state.lock().await;
        s.pending.remove(chat_id)
    };

    let Some(pending) = pending else {
        send_telegram(token, chat_id, "Pas de commande en attente.").await;
        return;
    };

    if cancelled {
        send_telegram(token, chat_id, "Commande annulée.").await;
        return;
    }

    // Execute the confirmed remediation command directly (bypass the confirmation loop)
    send_telegram(token, chat_id, &format!("Exécution en cours : {}", pending.command.summary)).await;

    let result = if let command_interpreter::ExecutionType::Remediation { ref cmd_id } = pending.command.execution_type {
        // Validate via whitelist and execute
        match crate::agent::remediation_whitelist::validate_remediation(cmd_id, &pending.command.params) {
            Ok(validated) => {
                match crate::agent::executor::execute_validated(&validated) {
                    Ok(exec_result) => command_interpreter::CommandResult {
                        success: exec_result.success,
                        message: if exec_result.success {
                            format!("Action exécutée avec succès.\n`{}`\n{}", exec_result.rendered_cmd, exec_result.stdout)
                        } else {
                            format!("Échec de l'exécution.\n`{}`\n{}", exec_result.rendered_cmd, exec_result.stderr)
                        },
                        data: Some(json!({
                            "cmd_id": cmd_id, "executed": true,
                            "success": exec_result.success,
                            "stdout": exec_result.stdout,
                            "stderr": exec_result.stderr,
                        })),
                    },
                    Err(e) => command_interpreter::CommandResult {
                        success: false,
                        message: format!("Erreur d'exécution : {:?}", e),
                        data: Some(json!({ "cmd_id": cmd_id, "executed": false })),
                    },
                }
            }
            Err(e) => command_interpreter::CommandResult {
                success: false,
                message: format!("Commande refusée par la whitelist : {}", e),
                data: None,
            },
        }
    } else {
        // Non-remediation: just execute normally
        let llm_config = LlmRouterConfig::from_db_settings(store.as_ref()).await;
        command_interpreter::execute_command(&pending.command, store.as_ref(), &llm_config).await
    };

    let response = format_for_telegram(&result);
    let suggestion = suggest_followup(&pending.command, &result);
    let full_response = if let Some(sug) = &suggestion {
        format!("{}\n\n_{}_", response, sug)
    } else {
        response.clone()
    };

    send_telegram(token, chat_id, &full_response).await;
    record_history(state, chat_id, &response).await;

    // Audit
    let audit_key = format!("conv_bot_confirmed_{}_{}", pending.command.action, chrono::Utc::now().timestamp());
    let _ = store.set_setting("_audit", &audit_key, &json!({
        "action": pending.command.action, "target": pending.command.target,
        "channel": "telegram", "confirmed_by": chat_id,
        "success": result.success, "timestamp": chrono::Utc::now().to_rfc3339(),
    })).await;
}
