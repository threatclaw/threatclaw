/**
 * ThreatClaw Agent Control API — mode, kill switch, audit, soul.
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

// ── Types ──

export interface ModeInfo {
  id: string;
  name: string;
  description: string;
  react_enabled: boolean;
  auto_execute: boolean;
}

export interface AgentModeResponse {
  current_mode: string;
  mode_name: string;
  description: string;
  react_enabled: boolean;
  auto_execute: boolean;
  hitl_required: boolean;
  available_modes: ModeInfo[];
}

export interface KillSwitchStatus {
  active: boolean;
  kill_reason: string | null;
}

export interface SoulInfo {
  status: string;
  name?: string;
  version?: string;
  purpose?: string;
  rules_count?: number;
  error?: string;
}

export interface AuditEntry {
  timestamp: string;
  event_type: string;
  agent_mode: string;
  cmd_id: string | null;
  approved_by: string | null;
  success: boolean | null;
  error_message: string | null;
}

// ── API ──

export async function fetchAgentMode(): Promise<AgentModeResponse> {
  return tcFetch("/agent/mode");
}

export async function setAgentMode(mode: string): Promise<void> {
  await tcFetch("/agent/mode", {
    method: "POST",
    body: JSON.stringify({ mode }),
  });
}

export async function fetchKillSwitch(): Promise<KillSwitchStatus> {
  return tcFetch("/agent/kill-switch");
}

export async function triggerKillSwitch(triggeredBy: string): Promise<void> {
  await tcFetch("/agent/kill-switch", {
    method: "POST",
    body: JSON.stringify({ triggered_by: triggeredBy }),
  });
}

export async function fetchAuditLog(limit = 50): Promise<{ entries: AuditEntry[]; total: number }> {
  return tcFetch(`/agent/audit?limit=${limit}`);
}

export async function fetchSoulInfo(): Promise<SoulInfo> {
  return tcFetch("/agent/soul");
}

// ── ReAct Cycle ──

export interface ReactAnalysis {
  analysis: string;
  severity: string;
  correlations: string[];
  proposed_actions: { cmd_id: string; params: Record<string, string>; rationale: string }[];
  injection_detected: boolean;
  confidence: number;
}

export interface ReactCycleResponse {
  status: string;
  observations: number;
  escalation_level: number;
  analysis: ReactAnalysis | null;
  error: string | null;
}

export async function triggerReactCycle(): Promise<ReactCycleResponse> {
  return tcFetch("/agent/react-cycle", { method: "POST" });
}

export async function fetchAuditEntries(): Promise<{ entries: AuditRawEntry[]; total: number }> {
  return tcFetch("/agent/audit");
}

export interface AuditRawEntry {
  event_type: string;
  agent_mode: string;
  cmd_id: string | null;
  success: boolean;
  summary: string | null;
  timestamp: string;
}
