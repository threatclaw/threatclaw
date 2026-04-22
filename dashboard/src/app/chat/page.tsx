"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";
import { Send, Loader2, Trash2, MessageSquarePlus, User, Bot, AlertTriangle } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
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

  const activeConv = conversations.find((c) => c.id === activeId) ?? null;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "240px 1fr",
        height: "calc(100vh - 140px)",
        minHeight: "500px",
        borderRadius: "12px",
        overflow: "hidden",
        border: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
      }}
    >
      {/* ═══ LEFT : conversation list ═══ */}
      <aside
        style={{
          display: "flex",
          flexDirection: "column",
          borderRight: "1px solid var(--tc-border)",
          background: "var(--tc-surface-alt, var(--tc-surface))",
          overflow: "hidden",
        }}
      >
        <button
          onClick={handleNewConversation}
          style={{
            margin: "12px",
            padding: "10px 12px",
            background: "var(--tc-red)",
            color: "#fff",
            border: "none",
            borderRadius: "8px",
            cursor: "pointer",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
            fontSize: "12px",
            fontWeight: 600,
            transition: "opacity 120ms",
          }}
          onMouseEnter={(e) => (e.currentTarget.style.opacity = "0.9")}
          onMouseLeave={(e) => (e.currentTarget.style.opacity = "1")}
        >
          <MessageSquarePlus size={14} />
          {tr("chatNewConversation", locale)}
        </button>
        <div style={{ flex: 1, overflowY: "auto", padding: "0 8px 12px" }}>
          {conversations.length === 0 ? (
            <div style={{ padding: "20px 10px", textAlign: "center", fontSize: "11px", color: "var(--tc-text-muted)" }}>
              {tr("chatNoConversations", locale)}
            </div>
          ) : (
            conversations.map((c) => (
              <div
                key={c.id}
                onClick={() => loadConversation(c.id)}
                style={{
                  padding: "10px 12px",
                  borderRadius: "8px",
                  cursor: "pointer",
                  marginBottom: "2px",
                  background: activeId === c.id ? "var(--tc-input)" : "transparent",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  transition: "background 120ms",
                }}
                onMouseEnter={(e) => {
                  if (activeId !== c.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)";
                }}
                onMouseLeave={(e) => {
                  if (activeId !== c.id) e.currentTarget.style.background = "transparent";
                }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: "12px",
                      fontWeight: activeId === c.id ? 600 : 500,
                      color: "var(--tc-text)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {c.title || (locale === "fr" ? "Sans titre" : "Untitled")}
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
                    color: "var(--tc-text-muted)",
                    opacity: 0,
                    transition: "opacity 120ms",
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.opacity = "1")}
                  onMouseLeave={(e) => (e.currentTarget.style.opacity = "0")}
                  onFocus={(e) => (e.currentTarget.style.opacity = "1")}
                  onBlur={(e) => (e.currentTarget.style.opacity = "0")}
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))
          )}
        </div>
      </aside>

      {/* ═══ RIGHT : the chat itself ═══ */}
      <section style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div ref={scrollRef} style={{ flex: 1, overflowY: "auto", padding: "24px 10% 24px 10%" }}>
          {loadingConv ? (
            <div style={{ textAlign: "center", padding: "40px" }}>
              <Loader2 size={18} className="animate-spin" style={{ color: "var(--tc-red)" }} />
            </div>
          ) : messages.length === 0 ? (
            <div
              style={{
                textAlign: "center",
                marginTop: "25vh",
                color: "var(--tc-text-muted)",
              }}
            >
              <Bot size={40} style={{ opacity: 0.3, marginBottom: "14px" }} />
              <div style={{ fontSize: "16px", fontWeight: 500, color: "var(--tc-text-sec)" }}>
                {tr("chatEmpty", locale)}
              </div>
            </div>
          ) : (
            <>
              {activeConv?.title && (
                <div
                  style={{
                    fontSize: "18px",
                    fontWeight: 600,
                    color: "var(--tc-text)",
                    marginBottom: "24px",
                    paddingBottom: "12px",
                    borderBottom: "1px solid var(--tc-border)",
                  }}
                >
                  {activeConv.title}
                </div>
              )}
              {messages.map((m) => (
                <MessageRow key={m.id} message={m} />
              ))}
              {sending && (
                <div style={{ display: "flex", alignItems: "center", gap: "8px", padding: "12px 4px", color: "var(--tc-text-muted)" }}>
                  <Loader2 size={14} className="animate-spin" />
                  <span style={{ fontSize: "12px" }}>{tr("chatThinking", locale)}</span>
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
                    fontSize: "11px",
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
            </>
          )}
        </div>

        {/* Input stuck at the bottom — no visible frame, just a subtle top border */}
        <div
          style={{
            borderTop: "1px solid var(--tc-border)",
            padding: "14px 10%",
            background: "var(--tc-surface)",
          }}
        >
          <div
            style={{
              display: "flex",
              gap: "8px",
              alignItems: "flex-end",
              background: "var(--tc-input)",
              border: "1px solid var(--tc-border)",
              borderRadius: "12px",
              padding: "6px",
              maxWidth: "900px",
              margin: "0 auto",
            }}
          >
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
                padding: "8px 10px",
                background: "transparent",
                border: "none",
                color: "var(--tc-text)",
                fontSize: "13px",
                fontFamily: "inherit",
                resize: "none",
                maxHeight: "160px",
                outline: "none",
              }}
            />
            <button
              onClick={handleSend}
              disabled={sending || !input.trim()}
              style={{
                background: input.trim() && !sending ? "var(--tc-red)" : "var(--tc-input)",
                color: input.trim() && !sending ? "#fff" : "var(--tc-text-muted)",
                border: "none",
                borderRadius: "8px",
                padding: "8px 12px",
                cursor: input.trim() && !sending ? "pointer" : "not-allowed",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                transition: "background 120ms",
              }}
              aria-label={tr("chatSend", locale)}
            >
              {sending ? <Loader2 size={14} className="animate-spin" /> : <Send size={14} />}
            </button>
          </div>
        </div>
      </section>
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
