/**
 * ThreatClaw Chat API — dashboard conversational pane (non-streaming).
 * Mirrors /api/tc/chat + /api/tc/conversations* defined in
 * src/channels/web/handlers/web_chat.rs.
 */

const BASE = "/api/tc";

async function tcFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "Unknown error");
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

export interface ChatResponse {
  conversation_id: string;
  user_message_id: string;
  assistant_message_id: string;
  content: string;
  tool_calls: unknown | null;
  success: boolean;
}

export interface ConversationSummary {
  id: string;
  title: string | null;
  message_count: number;
  started_at: string;
  last_activity: string;
  channel: string;
}

export interface ConversationMessage {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  created_at: string;
}

export async function sendChatMessage(
  message: string,
  conversationId?: string,
  userId: string = "rssi",
): Promise<ChatResponse> {
  return tcFetch<ChatResponse>("/chat", {
    method: "POST",
    body: JSON.stringify({
      message,
      conversation_id: conversationId,
      user_id: userId,
    }),
  });
}

export async function listConversations(
  userId: string = "rssi",
  limit: number = 50,
): Promise<{ conversations: ConversationSummary[] }> {
  return tcFetch(`/conversations?user_id=${encodeURIComponent(userId)}&limit=${limit}`);
}

export async function listConversationMessages(
  conversationId: string,
  limit: number = 50,
): Promise<{ messages: ConversationMessage[]; has_more: boolean }> {
  return tcFetch(`/conversations/${conversationId}/messages?limit=${limit}`);
}

export async function deleteConversation(conversationId: string): Promise<void> {
  await tcFetch(`/conversations/${conversationId}`, { method: "DELETE" });
}
