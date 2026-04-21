"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { Send, Loader2, Trash2, MessageSquarePlus, User, Bot, AlertTriangle } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import {
  sendChatMessage,
  listConversations,
  listConversationMessages,
  deleteConversation,
  type ConversationSummary,
  type ConversationMessage,
} from "@/lib/tc-chat-api";

interface LocalMessage extends ConversationMessage {
  pending?: boolean;
  failed?: boolean;
}

export default function ChatPage() {
  const locale = useLocale();
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [messages, setMessages] = useState<LocalMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [loadingConv, setLoadingConv] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const refreshConversations = useCallback(async () => {
    try {
      const { conversations: list } = await listConversations();
      setConversations(list);
    } catch (e) {
      console.error("listConversations failed", e);
    }
  }, []);

  useEffect(() => {
    refreshConversations();
  }, [refreshConversations]);

  const loadConversation = useCallback(async (id: string) => {
    setLoadingConv(true);
    setError(null);
    try {
      const { messages: msgs } = await listConversationMessages(id, 100);
      setMessages(msgs as LocalMessage[]);
      setActiveId(id);
    } catch (e) {
      console.error("loadConversation failed", e);
      setError(String(e));
    } finally {
      setLoadingConv(false);
    }
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const handleNewConversation = () => {
    setActiveId(null);
    setMessages([]);
    setError(null);
    inputRef.current?.focus();
  };

  const handleSend = async () => {
    const trimmed = input.trim();
    if (!trimmed || sending) return;

    setError(null);
    setSending(true);

    const optimisticUser: LocalMessage = {
      id: `pending-user-${Date.now()}`,
      role: "user",
      content: trimmed,
      created_at: new Date().toISOString(),
      pending: true,
    };
    setMessages((prev) => [...prev, optimisticUser]);
    setInput("");

    try {
      const resp = await sendChatMessage(trimmed, activeId ?? undefined);
      setMessages((prev) => {
        const withoutPending = prev.filter((m) => m.id !== optimisticUser.id);
        return [
          ...withoutPending,
          {
            id: resp.user_message_id,
            role: "user",
            content: trimmed,
            created_at: optimisticUser.created_at,
          },
          {
            id: resp.assistant_message_id,
            role: "assistant",
            content: resp.content,
            created_at: new Date().toISOString(),
          },
        ];
      });
      if (!activeId) {
        setActiveId(resp.conversation_id);
      }
      refreshConversations();
    } catch (e) {
      console.error("sendChatMessage failed", e);
      setError(tr("chatFailed", locale));
      setMessages((prev) =>
        prev.map((m) => (m.id === optimisticUser.id ? { ...m, pending: false, failed: true } : m)),
      );
    } finally {
      setSending(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await deleteConversation(id);
      if (activeId === id) {
        setActiveId(null);
        setMessages([]);
      }
      refreshConversations();
    } catch (err) {
      console.error("deleteConversation failed", err);
    }
  };

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "260px 1fr",
        gap: "16px",
        height: "calc(100vh - 120px)",
        minHeight: "500px",
      }}
    >
      {/* Sidebar — conversation list */}
      <NeuCard style={{ padding: "12px", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <ChromeButton
          onClick={handleNewConversation}
          style={{ width: "100%", marginBottom: "10px", justifyContent: "center" }}
        >
          <MessageSquarePlus size={13} />
          <span style={{ marginLeft: "6px" }}>{tr("chatNewConversation", locale)}</span>
        </ChromeButton>
        <div style={{ flex: 1, overflowY: "auto", margin: "-4px", padding: "4px" }}>
          {conversations.length === 0 ? (
            <div style={{ padding: "16px 8px", textAlign: "center" }}>
              <ChromeEmbossedText style={{ fontSize: "10px", opacity: 0.5 }}>
                {tr("chatNoConversations", locale)}
              </ChromeEmbossedText>
            </div>
          ) : (
            conversations.map((c) => (
              <div
                key={c.id}
                onClick={() => loadConversation(c.id)}
                style={{
                  padding: "8px 10px",
                  borderRadius: "8px",
                  cursor: "pointer",
                  marginBottom: "4px",
                  background: activeId === c.id ? "var(--tc-red-soft)" : "transparent",
                  border: activeId === c.id ? "0.5px solid var(--tc-red-border)" : "0.5px solid transparent",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  transition: "background 120ms",
                }}
                onMouseEnter={(e) => {
                  if (activeId !== c.id) e.currentTarget.style.background = "var(--tc-input)";
                }}
                onMouseLeave={(e) => {
                  if (activeId !== c.id) e.currentTarget.style.background = "transparent";
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: "11px",
                      fontWeight: 600,
                      color: activeId === c.id ? "var(--tc-red)" : "var(--tc-text)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {c.title || "—"}
                  </div>
                  <div style={{ fontSize: "9px", color: "var(--tc-text-sec)", marginTop: "2px" }}>
                    {c.message_count} msg · {new Date(c.last_activity).toLocaleDateString(locale)}
                  </div>
                </div>
                <button
                  onClick={(e) => handleDelete(c.id, e)}
                  title={tr("chatDelete", locale)}
                  style={{
                    background: "transparent",
                    border: "none",
                    cursor: "pointer",
                    padding: "3px",
                    color: "var(--tc-text-sec)",
                    opacity: 0.5,
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = "1")}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = "0.5")}
                >
                  <Trash2 size={11} />
                </button>
              </div>
            ))
          )}
        </div>
      </NeuCard>

      {/* Main pane — messages + input */}
      <NeuCard style={{ padding: "0", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: "20px" }}>
          {loadingConv ? (
            <div style={{ textAlign: "center", padding: "40px" }}>
              <Loader2 size={18} className="animate-spin" style={{ color: "var(--tc-red)" }} />
            </div>
          ) : messages.length === 0 ? (
            <div
              style={{
                textAlign: "center",
                marginTop: "80px",
                color: "var(--tc-text-sec)",
              }}
            >
              <MessageSquarePlus size={36} style={{ opacity: 0.3, marginBottom: "12px" }} />
              <ChromeEmbossedText style={{ fontSize: "11px", opacity: 0.6 }}>
                {tr("chatEmpty", locale)}
              </ChromeEmbossedText>
            </div>
          ) : (
            messages.map((m) => <MessageRow key={m.id} message={m} />)
          )}
          {sending && (
            <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "12px 4px", color: "var(--tc-text-sec)" }}>
              <Loader2 size={12} className="animate-spin" />
              <span style={{ fontSize: "10px" }}>{tr("chatThinking", locale)}</span>
            </div>
          )}
          {error && (
            <div
              style={{
                padding: "10px 12px",
                background: "rgba(208,48,32,0.08)",
                border: "0.5px solid var(--tc-red-border)",
                borderRadius: "8px",
                color: "var(--tc-red)",
                fontSize: "10px",
                display: "flex",
                alignItems: "center",
                gap: "6px",
                marginTop: "8px",
              }}
            >
              <AlertTriangle size={11} />
              {error}
            </div>
          )}
        </div>

        {/* Input area */}
        <div
          style={{
            borderTop: "0.5px solid var(--tc-border)",
            padding: "12px 16px",
            background: "var(--tc-card-inset)",
          }}
        >
          <div style={{ display: "flex", gap: "8px", alignItems: "flex-end" }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={tr("chatAsk", locale)}
              rows={1}
              disabled={sending}
              style={{
                flex: 1,
                padding: "9px 12px",
                background: "var(--tc-input)",
                border: "0.5px solid var(--tc-border)",
                borderRadius: "10px",
                color: "var(--tc-text)",
                fontSize: "12px",
                fontFamily: "inherit",
                resize: "none",
                maxHeight: "120px",
                outline: "none",
              }}
            />
            <ChromeButton
              onClick={handleSend}
              disabled={sending || !input.trim()}
              style={{ alignSelf: "stretch" }}
            >
              {sending ? <Loader2 size={13} className="animate-spin" /> : <Send size={13} />}
            </ChromeButton>
          </div>
        </div>
      </NeuCard>
    </div>
  );
}

function MessageRow({ message }: { message: LocalMessage }) {
  const isUser = message.role === "user";
  const isAssistant = message.role === "assistant";
  return (
    <div
      style={{
        display: "flex",
        gap: "10px",
        padding: "10px 0",
        opacity: message.pending ? 0.5 : 1,
      }}
    >
      <div
        style={{
          width: "26px",
          height: "26px",
          borderRadius: "50%",
          flexShrink: 0,
          background: isUser ? "var(--tc-input)" : "var(--tc-red-soft)",
          border: "0.5px solid var(--tc-border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: isUser ? "var(--tc-text-sec)" : "var(--tc-red)",
        }}
      >
        {isUser ? <User size={13} /> : <Bot size={13} />}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: "10px", color: "var(--tc-text-sec)", marginBottom: "3px" }}>
          {isUser ? "Vous" : isAssistant ? "ThreatClaw" : message.role}
          {message.failed && (
            <span style={{ marginLeft: "6px", color: "var(--tc-red)" }}>· échec</span>
          )}
        </div>
        <div
          style={{
            fontSize: "12px",
            color: "var(--tc-text)",
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
            lineHeight: 1.5,
          }}
        >
          {message.content}
        </div>
      </div>
    </div>
  );
}
