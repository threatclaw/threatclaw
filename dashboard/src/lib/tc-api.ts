/**
 * ThreatClaw API client — fetches real data from the Core API via Next.js proxy.
 * All requests go through /api/tc/* which proxies to the Rust backend.
 */

export interface DashboardMetrics {
  security_score: number;
  findings_critical: number;
  findings_high: number;
  findings_medium: number;
  findings_low: number;
  alerts_total: number;
  alerts_new: number;
  cloud_score: number;
  darkweb_leaks: number;
}

export interface Finding {
  id: number;
  skill_id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  category: string | null;
  asset: string | null;
  source: string | null;
  metadata: Record<string, unknown>;
  detected_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
}

export interface Alert {
  id: number;
  rule_id: string;
  level: string;
  title: string;
  status: string;
  hostname: string | null;
  source_ip: string | null;
  username: string | null;
  matched_at: string;
  matched_fields: Record<string, unknown> | null;
}

export interface CountEntry {
  label: string;
  count: number;
}

export interface SkillConfigEntry {
  skill_id: string;
  key: string;
  value: string;
}

export interface HealthResponse {
  status: string;
  version: string;
  database: boolean;
  llm: string;
}

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

// ── Health ──

export async function fetchHealth(): Promise<HealthResponse> {
  return tcFetch("/health");
}

// ── Metrics ──

export async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  const res = await tcFetch<{ metrics: DashboardMetrics }>("/metrics");
  return res.metrics;
}

// ── Findings ──

export async function fetchFindings(params?: {
  severity?: string;
  status?: string;
  skill_id?: string;
  limit?: number;
}): Promise<{ findings: Finding[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.severity) qs.set("severity", params.severity);
  if (params?.status) qs.set("status", params.status);
  if (params?.skill_id) qs.set("skill_id", params.skill_id);
  if (params?.limit) qs.set("limit", String(params.limit));
  const q = qs.toString();
  return tcFetch(`/findings${q ? `?${q}` : ""}`);
}

export async function fetchFindingsCounts(): Promise<CountEntry[]> {
  const res = await tcFetch<{ counts: CountEntry[] }>("/findings/counts");
  return res.counts;
}

export async function updateFindingStatus(
  id: number,
  status: string,
  resolvedBy?: string
): Promise<void> {
  await tcFetch(`/findings/${id}/status`, {
    method: "PUT",
    body: JSON.stringify({ status, resolved_by: resolvedBy }),
  });
}

// ── Alerts ──

export async function fetchAlerts(params?: {
  level?: string;
  status?: string;
  limit?: number;
}): Promise<{ alerts: Alert[]; total: number }> {
  const qs = new URLSearchParams();
  if (params?.level) qs.set("level", params.level);
  if (params?.status) qs.set("status", params.status);
  if (params?.limit) qs.set("limit", String(params.limit));
  const q = qs.toString();
  return tcFetch(`/alerts${q ? `?${q}` : ""}`);
}

export async function fetchAlertsCounts(): Promise<CountEntry[]> {
  const res = await tcFetch<{ counts: CountEntry[] }>("/alerts/counts");
  return res.counts;
}

// ── Skill Config ──

export async function fetchSkillConfig(
  skillId: string
): Promise<Record<string, string>> {
  const res = await tcFetch<{ config: SkillConfigEntry[] }>(
    `/config/${skillId}`
  );
  const map: Record<string, string> = {};
  for (const c of res.config) {
    map[c.key] = c.value;
  }
  return map;
}

export async function setSkillConfig(
  skillId: string,
  key: string,
  value: string
): Promise<void> {
  await tcFetch(`/config/${skillId}`, {
    method: "POST",
    body: JSON.stringify({ key, value }),
  });
}
