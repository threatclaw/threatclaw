"use client";

import React, { useState, useCallback } from "react";
import { Download, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { t as tr, Locale } from "@/lib/i18n";

interface Props {
  ollamaUrl: string;
  onComplete?: () => void;
  locale?: Locale;
}

interface PullState {
  status: "idle" | "pulling" | "done" | "error";
  model: string;
  progress: number; // 0-100
  downloaded: string;
  total: string;
  message: string;
}

export default function ModelPullProgress({ ollamaUrl, onComplete, locale = "fr" }: Props) {
  const [pullModel, setPullModel] = useState("");
  const [state, setState] = useState<PullState>({
    status: "idle", model: "", progress: 0, downloaded: "", total: "", message: "",
  });

  const pull = useCallback(async () => {
    if (!pullModel.trim()) return;

    setState({ status: "pulling", model: pullModel, progress: 0, downloaded: "", total: "", message: tr("connecting", locale) });

    try {
      // Ollama pull API streams NDJSON progress
      const resp = await fetch(`${ollamaUrl}/api/pull`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: pullModel, stream: true }),
      });

      if (!resp.ok || !resp.body) {
        setState(s => ({ ...s, status: "error", message: `HTTP ${resp.status}` }));
        return;
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const data = JSON.parse(line);

            if (data.status === "success") {
              setState(s => ({ ...s, status: "done", progress: 100, message: `${s.model} ${tr("modelPullDone", locale)}` }));
              onComplete?.();
              return;
            }

            if (data.total && data.completed) {
              const pct = Math.round((data.completed / data.total) * 100);
              const dlMB = (data.completed / 1e6).toFixed(0);
              const totalMB = (data.total / 1e6).toFixed(0);
              setState(s => ({
                ...s,
                progress: pct,
                downloaded: `${dlMB} MB`,
                total: `${totalMB} MB`,
                message: data.status || tr("downloading", locale),
              }));
            } else if (data.status) {
              setState(s => ({ ...s, message: data.status }));
            }
          } catch {}
        }
      }

      // If we get here without success, check final state
      setState(s => s.status === "done" ? s : { ...s, status: "done", progress: 100, message: tr("finished", locale) });
      onComplete?.();
    } catch (e: any) {
      setState(s => ({ ...s, status: "error", message: e.message || tr("networkError", locale) }));
    }
  }, [pullModel, ollamaUrl, onComplete]);

  const barColor = state.status === "error" ? "var(--tc-red)" :
                   state.status === "done" ? "var(--tc-green)" : "var(--tc-blue)";

  return (
    <div>
      {/* Input + button */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "8px" }}>
        <input
          type="text" value={pullModel}
          onChange={e => setPullModel(e.target.value)}
          onKeyDown={e => e.key === "Enter" && pull()}
          placeholder={tr("modelNamePlaceholder", locale)}
          disabled={state.status === "pulling"}
          style={{
            flex: 1, padding: "8px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
            background: "var(--tc-input)", border: "1px solid var(--tc-border)",
            color: "var(--tc-text)", outline: "none", fontFamily: "monospace",
          }}
        />
        <button
          className="tc-btn-embossed"
          onClick={pull}
          disabled={state.status === "pulling" || !pullModel.trim()}
        >
          {state.status === "pulling" ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
          {state.status === "pulling" ? "..." : "Pull"}
        </button>
      </div>

      {/* Progress bar */}
      {state.status !== "idle" && (
        <div style={{ marginTop: "8px" }}>
          {/* Bar */}
          <div style={{
            height: "8px", borderRadius: "4px", background: "var(--tc-input)", overflow: "hidden",
          }}>
            <div style={{
              height: "100%", borderRadius: "4px", background: barColor,
              width: `${state.progress}%`,
              transition: "width 300ms ease-out",
            }} />
          </div>

          {/* Status line */}
          <div style={{
            display: "flex", justifyContent: "space-between", marginTop: "4px",
            fontSize: "10px", color: "var(--tc-text-muted)",
          }}>
            <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              {state.status === "done" && <CheckCircle2 size={10} color="var(--tc-green)" />}
              {state.status === "error" && <XCircle size={10} color="var(--tc-red)" />}
              {state.status === "pulling" && <Loader2 size={10} className="animate-spin" />}
              {state.message}
            </span>
            <span>
              {state.downloaded && state.total && `${state.downloaded} / ${state.total}`}
              {state.progress > 0 && ` (${state.progress}%)`}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
