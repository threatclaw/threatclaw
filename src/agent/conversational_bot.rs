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

/// State for the conversational bot.
struct BotState {
    /// Pending confirmations per chat_id.
    pending: HashMap<String, PendingConfirmation>,
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
            last_update_id: 0,
        }));

        // Wait for backend to be ready
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        loop {
            tokio::time::sleep(poll_interval).await;

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
                let message = &update["message"];
                let text = message["text"].as_str().unwrap_or("");
                let chat_id = message["chat"]["id"].as_i64().unwrap_or(0).to_string();
                let from = message["from"]["username"].as_str().unwrap_or("unknown");

                // Update offset
                {
                    let mut s = state.lock().await;
                    if update_id > s.last_update_id {
                        s.last_update_id = update_id;
                    }
                }

                if text.is_empty() { continue; }

                // Security: only process messages from allowed chat
                if !allowed_chat_id.is_empty() && chat_id != allowed_chat_id {
                    tracing::warn!("CONV_BOT: Ignoring message from unauthorized chat_id={chat_id} (expected {allowed_chat_id})");
                    continue;
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
        }
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
            ("allowed_updates", "[\"message\"]".to_string()),
        ])
        .send().await
        .map_err(|e| e.to_string())?;

    let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;

    if data["ok"].as_bool() != Some(true) {
        return Err(format!("Telegram API error: {}", data["description"].as_str().unwrap_or("unknown")));
    }

    Ok(data["result"].as_array().cloned().unwrap_or_default())
}

/// Send a message to a Telegram chat.
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
    // Load LLM config
    let llm_config = LlmRouterConfig::from_db_settings(store.as_ref()).await;

    // Parse the command
    let cmd = command_interpreter::parse_command(text, &llm_config).await;

    match &cmd.execution_type {
        ExecutionType::Unknown => {
            send_telegram(token, chat_id, &format!(
                "Commande non reconnue.\n\nCommandes disponibles :\n\
                - *scan* [IP] — scanner une cible\n\
                - *status* — état du système\n\
                - *findings* — findings ouverts\n\
                - *alerts* — alertes Sigma\n\
                - *playbook* [contexte] — générer un playbook\n\
                - *rapport* — générer un rapport\n\
                - *block* [IP] — bloquer une IP\n\
                - *react* — lancer une analyse"
            )).await;
        }
        ExecutionType::Remediation { .. } => {
            // Need confirmation for remediation actions
            send_telegram(token, chat_id, &format_confirmation_request(&cmd)).await;
            let mut s = state.lock().await;
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
            send_telegram(token, chat_id, &format_for_telegram(&result)).await;

            // Audit
            let audit_key = format!("conv_bot_{}_{}", cmd.action, chrono::Utc::now().timestamp());
            let _ = store.set_setting("_audit", &audit_key, &json!({
                "action": cmd.action, "target": cmd.target, "channel": "telegram",
                "success": result.success, "timestamp": chrono::Utc::now().to_rfc3339(),
            })).await;
        }
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

    // Execute the confirmed command
    send_telegram(token, chat_id, &format!("⏳ Exécution : {}", pending.command.summary)).await;
    let llm_config = LlmRouterConfig::from_db_settings(store.as_ref()).await;
    let result = command_interpreter::execute_command(&pending.command, store.as_ref(), &llm_config).await;
    send_telegram(token, chat_id, &format_for_telegram(&result)).await;

    // Audit
    let audit_key = format!("conv_bot_confirmed_{}_{}", pending.command.action, chrono::Utc::now().timestamp());
    let _ = store.set_setting("_audit", &audit_key, &json!({
        "action": pending.command.action, "target": pending.command.target,
        "channel": "telegram", "confirmed_by": chat_id,
        "success": result.success, "timestamp": chrono::Utc::now().to_rfc3339(),
    })).await;
}
