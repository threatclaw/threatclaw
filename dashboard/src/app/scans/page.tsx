"use client";

import React, { useEffect, useState, useCallback } from "react";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import {
  Play, Clock, Bell, Puzzle, RefreshCw, CheckCircle2, X, Loader2,
  AlertTriangle, Crosshair,
  Network, Container, Shield, FileText, Code, Key, Globe,
} from "lucide-react";

interface ScanJob {
  id: number;
  target: string;
  scan_type: string;
  status: string;
  asset_id: string | null;
  requested_by: string;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  result_json: any;
  error_msg: string | null;
  ttl_seconds: number;
  worker_id: string | null;
}

interface SkillManifest {
  id: string;
  name: string;
  version?: string;
  description: string;
  type: string;
  category: string;
  advanced?: boolean;
  config?: Record<string, any> | null;
}

interface ScanType {
  value: string;
  label: string;
  description: string;
  target_label: string;
  target_placeholder: string;
  icon: React.ElementType;
  color: string;
  advanced: boolean;
}

function getScanTypes(locale: Locale): ScanType[] {
  return [
  // ── Outils principaux (RSSI standard) ──
  {
    value: "nmap_fingerprint",
    label: tr("scans_nmapLabel", locale),
    description: tr("scans_nmapDesc", locale),
    target_label: tr("scans_nmapTargetLabel", locale),
    target_placeholder: "10.0.0.50  ou  10.0.0.0/24",
    icon: Network,
    color: "#d03020",
    advanced: false,
  },
  {
    value: "trivy_image",
    label: tr("scans_trivyLabel", locale),
    description: tr("scans_trivyDesc", locale),
    target_label: tr("scans_trivyTargetLabel", locale),
    target_placeholder: "nginx:latest",
    icon: Container,
    color: "#3080d0",
    advanced: false,
  },
  {
    value: "lynis_audit",
    label: tr("scans_lynisLabel", locale),
    description: tr("scans_lynisDesc", locale),
    target_label: tr("scans_lynisTargetLabel", locale),
    target_placeholder: tr("scans_lynisTargetPlaceholder", locale),
    icon: Shield,
    color: "#30a050",
    advanced: false,
  },
  {
    value: "docker_bench",
    label: tr("scans_dockerBenchLabel", locale),
    description: tr("scans_dockerBenchDesc", locale),
    target_label: tr("scans_dockerBenchTargetLabel", locale),
    target_placeholder: "n/a",
    icon: Container,
    color: "#9060d0",
    advanced: false,
  },

  // ── Outils avancés (dev / pentest / niche) ──
  {
    value: "syft_sbom",
    label: "Syft — SBOM",
    description: tr("scans_syftDesc", locale),
    target_label: tr("scans_syftTargetLabel", locale),
    target_placeholder: "nginx:latest",
    icon: FileText,
    color: "#06b6d4",
    advanced: true,
  },
  {
    value: "semgrep_scan",
    label: "Semgrep — SAST",
    description: tr("scans_semgrepDesc", locale),
    target_label: tr("scans_semgrepTargetLabel", locale),
    target_placeholder: "/srv/repos/mon-app",
    icon: Code,
    color: "#d09020",
    advanced: true,
  },
  {
    value: "checkov_scan",
    label: "Checkov — IaC",
    description: tr("scans_checkovDesc", locale),
    target_label: tr("scans_checkovTargetLabel", locale),
    target_placeholder: "/srv/repos/terraform",
    icon: Code,
    color: "#06b6d4",
    advanced: true,
  },
  {
    value: "trufflehog_scan",
    label: "TruffleHog — secrets",
    description: tr("scans_trufflehogDesc", locale),
    target_label: tr("scans_trufflehogTargetLabel", locale),
    target_placeholder: "/srv/repos/mon-app",
    icon: Key,
    color: "#e84040",
    advanced: true,
  },
  {
    value: "zap_scan",
    label: "OWASP ZAP — DAST",
    description: tr("scans_zapDesc", locale),
    target_label: tr("scans_zapTargetLabel", locale),
    target_placeholder: "https://example.com",
    icon: Globe,
    color: "#ff6020",
    advanced: true,
  },
  ];
}

function formatDuration(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m${Math.floor((ms % 60_000) / 1000)}s`;
}

function relTime(iso: string | null, locale: Locale): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const diff = Date.now() - t;
  if (diff < 60_000) return tr("scans_justNow", locale);
  if (diff < 3_600_000) { const m = Math.floor(diff / 60_000); return locale === "fr" ? `il y a ${m} min` : `${m} min ago`; }
  if (diff < 86_400_000) { const h = Math.floor(diff / 3_600_000); return locale === "fr" ? `il y a ${h} h` : `${h}h ago`; }
  return new Date(iso).toLocaleString(locale === "fr" ? "fr-FR" : "en-US");
}

function statusPill(status: string, locale: Locale) {
  const colors: Record<string, { bg: string; fg: string; border: string; label: string }> = {
    queued: { bg: "rgba(208,144,32,0.10)", fg: "#d09020", border: "rgba(208,144,32,0.25)", label: tr("scans_statusQueued", locale) },
    running: { bg: "rgba(48,128,208,0.10)", fg: "#3080d0", border: "rgba(48,128,208,0.25)", label: tr("scans_statusRunning", locale) },
    done: { bg: "rgba(48,160,80,0.10)", fg: "#30a050", border: "rgba(48,160,80,0.25)", label: tr("scans_statusDone", locale) },
    error: { bg: "rgba(208,48,32,0.10)", fg: "#d03020", border: "rgba(208,48,32,0.25)", label: tr("scans_statusError", locale) },
    skipped: { bg: "rgba(140,140,140,0.10)", fg: "var(--tc-text-muted)", border: "rgba(140,140,140,0.25)", label: tr("scans_statusSkipped", locale) },
  };
  const c = colors[status] || colors.skipped;
  return (
    <span style={{
      fontSize: "9px", fontWeight: 800, padding: "2px 7px", borderRadius: "4px",
      background: c.bg, color: c.fg, border: `1px solid ${c.border}`,
      textTransform: "uppercase", letterSpacing: "0.04em", whiteSpace: "nowrap",
    }}>{c.label}</span>
  );
}

export default function ScansPage() {
  const locale = useLocale();
  const [tab, setTab] = useState<"launch" | "history" | "scheduled" | "library">("launch");

  // URL → tab sync (sidebar drives ?tab=)
  useEffect(() => {
    const sync = () => {
      const t = new URLSearchParams(window.location.search).get("tab");
      if (t === "history" || t === "scheduled" || t === "library") setTab(t);
      else setTab("launch");
    };
    sync();
    window.addEventListener("popstate", sync);
    window.addEventListener("tc:history", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("tc:history", sync);
    };
  }, []);

  return (
    <div style={{ padding: "0 24px 40px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px", flexWrap: "wrap", gap: "12px" }}>
        <h1 style={{ fontSize: "22px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>
          Scans
          <span style={{ fontSize: "12px", fontWeight: 500, color: "var(--tc-text-muted)", marginLeft: "10px" }}>
            {tab === "launch" && tr("scans_subtitleLaunch", locale)}
            {tab === "history" && tr("scans_subtitleHistory", locale)}
            {tab === "scheduled" && tr("scans_subtitleScheduled", locale)}
            {tab === "library" && tr("scans_subtitleLibrary", locale)}
          </span>
        </h1>
      </div>

      {tab === "launch" && <LaunchTab locale={locale} />}
      {tab === "history" && <HistoryTab locale={locale} />}
      {tab === "scheduled" && <ScheduledTab locale={locale} />}
      {tab === "library" && <LibraryTab locale={locale} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function LaunchTab({ locale }: { locale: Locale }) {
  const [selected, setSelected] = useState<ScanType | null>(null);
  const [target, setTarget] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const scanTypes = getScanTypes(locale);
  const principal = scanTypes.filter(t => !t.advanced);
  const advanced = scanTypes.filter(t => t.advanced);

  const pick = (t: ScanType) => {
    setSelected(t);
    setTarget("");
    setResult(null);
  };

  const launch = async () => {
    if (!selected) return;
    // docker_bench has no target field — pass a placeholder so backend
    // validation doesn't reject the empty string.
    const finalTarget = selected.value === "docker_bench" ? "host" : target.trim();
    if (!finalTarget) return;
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch("/api/tc/scans/queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: finalTarget, scan_type: selected.value, ttl_seconds: 0 }),
      });
      const data = await res.json();
      if (!res.ok) {
        setResult({ error: data.error || data.message || `HTTP ${res.status}` });
      } else {
        setResult(data);
      }
    } catch (e: any) {
      setResult({ error: e.message || String(e) });
    }
    setBusy(false);
  };

  return (
    <div>
      {!selected && (
        <>
          <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "16px", lineHeight: 1.6 }}>
            {tr("scans_launchIntro1", locale)} <strong>{tr("scans_principalWord", locale)}</strong> {tr("scans_launchIntro2", locale)}
            {tr("scans_launchIntro3", locale)} <strong>{tr("scans_advancedWord", locale)}</strong> {tr("scans_launchIntro4", locale)}
          </p>

          <SectionTitle title={tr("scans_principalTools", locale)} />
          <CardGrid types={principal} onPick={pick} />

          <div style={{ marginTop: "20px" }}>
            <button
              onClick={() => setShowAdvanced(!showAdvanced)}
              style={{
                fontSize: "11px", padding: "6px 10px", cursor: "pointer", fontFamily: "inherit",
                background: "transparent", color: "var(--tc-text-muted)",
                border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
              }}
            >
              {showAdvanced ? "▾" : "▸"} {tr("scans_advancedTools", locale)} ({advanced.length})
            </button>
            {showAdvanced && (
              <div style={{ marginTop: "12px" }}>
                <CardGrid types={advanced} onPick={pick} />
              </div>
            )}
          </div>
        </>
      )}

      {selected && (
        <div style={{ maxWidth: "560px" }}>
          <button
            onClick={() => { setSelected(null); setResult(null); }}
            style={{
              fontSize: "10px", padding: "5px 10px", cursor: "pointer", fontFamily: "inherit",
              background: "transparent", color: "var(--tc-text-muted)",
              border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", marginBottom: "14px",
            }}
          >
            ← {tr("scans_back", locale)}
          </button>

          <div style={{
            background: "var(--tc-neu-inner)",
            boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
            borderRadius: "var(--tc-radius-md)",
            padding: "20px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "10px" }}>
              <selected.icon size={18} color={selected.color} />
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--tc-text)" }}>{selected.label}</div>
              {selected.advanced && (
                <span style={{
                  fontSize: "8px", fontWeight: 800, padding: "2px 6px", borderRadius: "3px",
                  background: "rgba(208,144,32,0.12)", color: "var(--tc-amber)", textTransform: "uppercase",
                }}>{tr("scans_advancedBadge", locale)}</span>
              )}
            </div>
            <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.6, marginBottom: "16px" }}>
              {selected.description}
            </p>

            {selected.value !== "docker_bench" && (
              <div style={{ marginBottom: "14px" }}>
                <label style={{ fontSize: "11px", color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
                  {selected.target_label}
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder={selected.target_placeholder}
                  autoFocus
                  style={{
                    width: "100%", padding: "9px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
                    background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
                    fontFamily: "'JetBrains Mono', ui-monospace, monospace",
                  }}
                />
              </div>
            )}

            <button
              onClick={launch}
              disabled={busy || (selected.value !== "docker_bench" && !target.trim())}
              className="tc-btn-embossed"
              style={{ fontSize: "11px", padding: "10px 20px", width: "100%", justifyContent: "center" }}
            >
              {busy ? <><Loader2 size={12} className="animate-spin" /> {tr("scans_launching", locale)}</> : <><Play size={12} /> {tr("scans_launchScan", locale)}</>}
            </button>

            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "10px", lineHeight: 1.5 }}>
              {tr("scans_launchHint1", locale)} <strong>{tr("scans_historyTab", locale)}</strong>.
              {tr("scans_launchHint2", locale)}
            </div>
          </div>

          {result && (
            <div style={{
              marginTop: "16px", padding: "12px 14px", borderRadius: "var(--tc-radius-sm)",
              background: result.error ? "rgba(208,48,32,0.06)" : "rgba(48,160,80,0.06)",
              border: `1px solid ${result.error ? "rgba(208,48,32,0.22)" : "rgba(48,160,80,0.22)"}`,
            }}>
              {result.error ? (
                <div style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
                  <X size={14} color="#d03020" style={{ flexShrink: 0, marginTop: "1px" }} />
                  <div>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: "#d03020" }}>{tr("scans_failure", locale)}</div>
                    <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", marginTop: "3px" }}>{result.error}</div>
                  </div>
                </div>
              ) : result.queued ? (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <CheckCircle2 size={14} color="#30a050" />
                  <div style={{ fontSize: "12px", color: "var(--tc-text-sec)" }}>
                    {tr("scans_scanQueuedPrefix", locale)} #{result.scan_id} {tr("scans_scanQueuedSuffix", locale)} <a href="/scans?tab=history" style={{ color: "var(--tc-blue)" }}>{tr("scans_historyTab", locale)}</a>.
                  </div>
                </div>
              ) : (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <AlertTriangle size={14} color="var(--tc-amber)" />
                  <div style={{ fontSize: "12px", color: "var(--tc-text-sec)" }}>{result.reason || tr("scans_scanSkipped", locale)}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function SectionTitle({ title }: { title: string }) {
  return (
    <div style={{
      fontSize: "10px", fontWeight: 800, color: "var(--tc-text-muted)",
      textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "10px",
    }}>{title}</div>
  );
}

function CardGrid({ types, onPick }: { types: ScanType[]; onPick: (t: ScanType) => void }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: "10px" }}>
      {types.map(t => {
        const Icon = t.icon;
        return (
          <button
            key={t.value}
            onClick={() => onPick(t)}
            style={{
              textAlign: "left", padding: "14px",
              borderRadius: "var(--tc-radius-md)",
              background: "var(--tc-neu-inner)",
              boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
              border: "1px solid transparent",
              cursor: "pointer", fontFamily: "inherit",
              transition: "border 120ms",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.border = `1px solid ${t.color}40`; }}
            onMouseLeave={(e) => { e.currentTarget.style.border = "1px solid transparent"; }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
              <Icon size={16} color={t.color} />
              <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{t.label}</div>
            </div>
            <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.5, margin: 0 }}>
              {t.description}
            </p>
          </button>
        );
      })}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function HistoryTab({ locale }: { locale: Locale }) {
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const qs = new URLSearchParams();
      if (statusFilter) qs.set("status", statusFilter);
      qs.set("limit", "100");
      const res = await fetch(`/api/tc/scans?${qs}`);
      const data = await res.json();
      setScans(data.scans || []);
    } catch {}
    setLoading(false);
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);
  // Auto-refresh while there are running/queued scans
  useEffect(() => {
    const hasActive = scans.some(s => s.status === "queued" || s.status === "running");
    if (!hasActive) return;
    const interval = setInterval(load, 3000);
    return () => clearInterval(interval);
  }, [scans, load]);

  return (
    <div>
      <div style={{ display: "flex", gap: "8px", marginBottom: "14px", alignItems: "center" }}>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{
            padding: "6px 10px", borderRadius: "var(--tc-radius-input)", fontSize: "11px",
            background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
          }}
        >
          <option value="">{tr("scans_allStatuses", locale)}</option>
          <option value="queued">{tr("scans_filterQueued", locale)}</option>
          <option value="running">{tr("scans_filterRunning", locale)}</option>
          <option value="done">{tr("scans_filterDone", locale)}</option>
          <option value="error">{tr("scans_filterError", locale)}</option>
        </select>
        <button onClick={load} className="tc-btn-embossed" style={{ fontSize: "11px", padding: "6px 12px" }}>
          <RefreshCw size={12} /> {tr("scans_refresh", locale)}
        </button>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>{tr("scans_loading", locale)}</div>}
      {!loading && scans.length === 0 && (
        <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>
          {tr("scans_noScan", locale)} {statusFilter ? `${tr("scans_withStatus", locale)} "${statusFilter}"` : tr("scans_forNow", locale)}.
        </div>
      )}
      {!loading && scans.length > 0 && (
        <div style={{ borderRadius: "var(--tc-radius-md)", overflow: "hidden", border: "1px solid var(--tc-border)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", textAlign: "left", color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colType", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colTarget", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colStatus", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colDuration", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colWhen", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colOrigin", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colResult", locale)}</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace" }}>{s.scan_type}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis" }}>{s.target}</td>
                  <td style={{ padding: "8px 12px" }}>{statusPill(s.status, locale)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{formatDuration(s.duration_ms)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{relTime(s.requested_at, locale)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)", fontSize: "10px" }}>{s.requested_by}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>
                    {s.error_msg ? (
                      <span style={{ color: "#d03020" }} title={s.error_msg}>{s.error_msg.slice(0, 40)}{s.error_msg.length > 40 ? "..." : ""}</span>
                    ) : s.result_json ? (
                      <ResultSummary type={s.scan_type} result={s.result_json} />
                    ) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ResultSummary({ type, result }: { type: string; result: any }) {
  if (type === "nmap_fingerprint") {
    return (
      <span>
        {result.hosts_discovered ?? 0} host · {result.open_ports_total ?? 0} ports
      </span>
    );
  }
  if (type === "trivy_image") {
    return <span>{result.findings_created ?? 0} findings</span>;
  }
  return <span style={{ fontSize: "10px" }}>{JSON.stringify(result).slice(0, 50)}</span>;
}

// ─────────────────────────────────────────────────────────────────────
interface Schedule {
  id: number;
  scan_type: string;
  target: string;
  name: string | null;
  frequency: string;
  minute: number;
  hour: number | null;
  day_of_week: number | null;
  day_of_month: number | null;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string;
}

function getDOW(locale: Locale): string[] {
  return [
    tr("scans_monday", locale),
    tr("scans_tuesday", locale),
    tr("scans_wednesday", locale),
    tr("scans_thursday", locale),
    tr("scans_friday", locale),
    tr("scans_saturday", locale),
    tr("scans_sunday", locale),
  ];
}

function describeSchedule(s: Schedule, locale: Locale): string {
  const hh = String(s.hour ?? 0).padStart(2, "0");
  const mm = String(s.minute).padStart(2, "0");
  const DOW = getDOW(locale);
  switch (s.frequency) {
    case "hourly":
      return `${tr("scans_everyHourAt", locale)} :${mm}`;
    case "daily":
      return `${tr("scans_everyDayAt", locale)} ${hh}:${mm}`;
    case "weekly":
      return `${tr("scans_everyWeekday1", locale)} ${DOW[s.day_of_week ?? 0]} ${tr("scans_everyWeekday2", locale)} ${hh}:${mm}`;
    case "monthly":
      return `${tr("scans_everyMonth1", locale)} ${s.day_of_month ?? 1} ${tr("scans_everyMonth2", locale)} ${hh}:${mm}`;
    default:
      return s.frequency;
  }
}

function ScheduledTab({ locale }: { locale: Locale }) {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/tc/scans/schedules");
      const d = await r.json();
      setSchedules(d.schedules || []);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const remove = async (id: number) => {
    if (!confirm(tr("scans_confirmDelete", locale))) return;
    await fetch(`/api/tc/scans/schedules/${id}`, { method: "DELETE" });
    load();
  };

  const toggle = async (s: Schedule) => {
    await fetch(`/api/tc/scans/schedules/${s.id}/toggle`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: !s.enabled }),
    });
    load();
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
        <div style={{ fontSize: "11px", color: "var(--tc-text-muted)" }}>
          {schedules.length} {schedules.length > 1 ? tr("scans_schedulesPlural", locale) : tr("scans_schedulesSingular", locale)}
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="tc-btn-embossed"
          style={{ fontSize: "11px", padding: "6px 14px" }}
        >
          {showForm ? <>− {tr("scans_hideForm", locale)}</> : <><Bell size={12} /> {tr("scans_newSchedule", locale)}</>}
        </button>
      </div>

      {showForm && <NewScheduleForm locale={locale} onCreated={() => { setShowForm(false); load(); }} />}

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>{tr("scans_loading", locale)}</div>}
      {!loading && schedules.length === 0 && !showForm && (
        <div style={{
          padding: "20px", borderRadius: "var(--tc-radius-md)",
          background: "var(--tc-neu-inner)",
          boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
        }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "6px" }}>{tr("scans_noScheduleTitle", locale)}</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.6 }}>
            {tr("scans_noScheduleBody", locale)}
          </div>
        </div>
      )}
      {!loading && schedules.length > 0 && (
        <div style={{ borderRadius: "var(--tc-radius-md)", overflow: "hidden", border: "1px solid var(--tc-border)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", textAlign: "left", color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colName", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colType", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colTarget", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colFrequency", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colNext", locale)}</th>
                <th style={{ padding: "10px 12px" }}>{tr("scans_colStatus", locale)}</th>
                <th style={{ padding: "10px 12px", textAlign: "right" }}>{tr("scans_colActions", locale)}</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)" }}>{s.name || tr("scans_unnamed", locale)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace" }}>{s.scan_type}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis" }}>{s.target}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-sec)" }}>{describeSchedule(s, locale)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{relTime(s.next_run_at, locale)}</td>
                  <td style={{ padding: "8px 12px" }}>
                    <button
                      onClick={() => toggle(s)}
                      style={{
                        fontSize: "9px", fontWeight: 700, padding: "2px 8px", borderRadius: "4px", cursor: "pointer", fontFamily: "inherit",
                        background: s.enabled ? "rgba(48,160,80,0.10)" : "rgba(140,140,140,0.10)",
                        color: s.enabled ? "#30a050" : "var(--tc-text-muted)",
                        border: `1px solid ${s.enabled ? "rgba(48,160,80,0.25)" : "rgba(140,140,140,0.25)"}`,
                        textTransform: "uppercase",
                      }}
                    >
                      {s.enabled ? tr("scans_active", locale) : tr("scans_paused", locale)}
                    </button>
                  </td>
                  <td style={{ padding: "8px 12px", textAlign: "right" }}>
                    <button
                      onClick={() => remove(s.id)}
                      style={{
                        fontSize: "10px", padding: "4px 8px", cursor: "pointer", fontFamily: "inherit",
                        background: "transparent", color: "#d03020",
                        border: "1px solid rgba(208,48,32,0.25)", borderRadius: "var(--tc-radius-sm)",
                      }}
                    >{tr("scans_delete", locale)}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function NewScheduleForm({ locale, onCreated }: { locale: Locale; onCreated: () => void }) {
  const [scanType, setScanType] = useState<string>("nmap_fingerprint");
  const [target, setTarget] = useState<string>("");
  const [name, setName] = useState<string>("");
  const [frequency, setFrequency] = useState<"hourly" | "daily" | "weekly" | "monthly">("daily");
  const [hour, setHour] = useState<number>(2);
  const [minute, setMinute] = useState<number>(0);
  const [dayOfWeek, setDayOfWeek] = useState<number>(0);
  const [dayOfMonth, setDayOfMonth] = useState<number>(1);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!target.trim() && scanType !== "docker_bench") {
      setErr(tr("scans_targetRequired", locale));
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const body: any = {
        scan_type: scanType,
        target: scanType === "docker_bench" ? "host" : target.trim(),
        name: name.trim() || null,
        frequency,
        minute,
        hour: frequency === "hourly" ? null : hour,
        day_of_week: frequency === "weekly" ? dayOfWeek : null,
        day_of_month: frequency === "monthly" ? dayOfMonth : null,
      };
      const r = await fetch("/api/tc/scans/schedules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      onCreated();
    } catch (e: any) {
      setErr(e.message || String(e));
    }
    setBusy(false);
  };

  const scanTypes = getScanTypes(locale);
  const selectedType = scanTypes.find(t => t.value === scanType) || scanTypes[0];

  return (
    <div style={{
      marginBottom: "16px", padding: "16px",
      background: "var(--tc-neu-inner)",
      boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
      borderRadius: "var(--tc-radius-md)",
    }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_nameOptional", locale)}</label>
          <input
            type="text" value={name} onChange={(e) => setName(e.target.value)}
            placeholder={tr("scans_namePlaceholder", locale)}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          />
        </div>
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_scanType", locale)}</label>
          <select
            value={scanType} onChange={(e) => setScanType(e.target.value)}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          >
            {scanTypes.map(t => <option key={t.value} value={t.value}>{t.label}{t.advanced ? ` · ${tr("scans_advancedBadge", locale)}` : ""}</option>)}
          </select>
        </div>
      </div>

      {scanType !== "docker_bench" && (
        <div style={{ marginBottom: "12px" }}>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{selectedType.target_label}</label>
          <input
            type="text" value={target} onChange={(e) => setTarget(e.target.value)}
            placeholder={selectedType.target_placeholder}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", fontFamily: "'JetBrains Mono', ui-monospace, monospace", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          />
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: "10px", marginBottom: "12px" }}>
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_frequency", locale)}</label>
          <select
            value={frequency} onChange={(e) => setFrequency(e.target.value as any)}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          >
            <option value="hourly">{tr("scans_freqHourly", locale)}</option>
            <option value="daily">{tr("scans_freqDaily", locale)}</option>
            <option value="weekly">{tr("scans_freqWeekly", locale)}</option>
            <option value="monthly">{tr("scans_freqMonthly", locale)}</option>
          </select>
        </div>
        {frequency === "weekly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_day", locale)}</label>
            <select
              value={dayOfWeek} onChange={(e) => setDayOfWeek(parseInt(e.target.value))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            >
              {getDOW(locale).map((d, i) => <option key={i} value={i}>{d}</option>)}
            </select>
          </div>
        )}
        {frequency === "monthly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_dayOfMonth", locale)}</label>
            <input
              type="number" min={1} max={28} value={dayOfMonth} onChange={(e) => setDayOfMonth(parseInt(e.target.value || "1"))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            />
          </div>
        )}
        {frequency !== "hourly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_hour", locale)}</label>
            <input
              type="number" min={0} max={23} value={hour} onChange={(e) => setHour(parseInt(e.target.value || "0"))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            />
          </div>
        )}
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>{tr("scans_minute", locale)}</label>
          <input
            type="number" min={0} max={59} value={minute} onChange={(e) => setMinute(parseInt(e.target.value || "0"))}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          />
        </div>
      </div>

      {err && <div style={{ fontSize: "10px", color: "#d03020", marginBottom: "10px" }}>{err}</div>}

      <button
        onClick={submit} disabled={busy} className="tc-btn-embossed"
        style={{ fontSize: "11px", padding: "8px 16px" }}
      >
        {busy ? <><Loader2 size={12} className="animate-spin" /> {tr("scans_creating", locale)}</> : <><Bell size={12} /> {tr("scans_createSchedule", locale)}</>}
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function LibraryTab({ locale }: { locale: Locale }) {
  const [skills, setSkills] = useState<SkillManifest[]>([]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/tc/catalog")
      .then(r => r.json())
      .then((d: any) => {
        const tools: SkillManifest[] = (d.skills || []).filter((s: SkillManifest) => s.type === "tool");
        setSkills(tools);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const core = skills.filter(s => !s.advanced);
  const advanced = skills.filter(s => s.advanced);

  return (
    <div>
      <p style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "16px", lineHeight: 1.6 }}>
        {tr("scans_libraryIntro", locale)}
      </p>

      <SkillSection title={tr("scans_principalTools", locale)} skills={core} />

      {advanced.length > 0 && (
        <div style={{ marginTop: "24px" }}>
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{
              fontSize: "11px", padding: "6px 10px", cursor: "pointer", fontFamily: "inherit",
              background: "transparent", color: "var(--tc-text-muted)",
              border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            }}
          >
            {showAdvanced ? "▾" : "▸"} {tr("scans_advancedTools", locale)} ({advanced.length})
          </button>
          {showAdvanced && (
            <div style={{ marginTop: "12px" }}>
              <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "10px", fontStyle: "italic" }}>
                {tr("scans_libraryAdvancedNote", locale)}
              </p>
              <SkillSection title="" skills={advanced} />
            </div>
          )}
        </div>
      )}

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>{tr("scans_loading", locale)}</div>}
    </div>
  );
}

function SkillSection({ title, skills }: { title: string; skills: SkillManifest[] }) {
  if (skills.length === 0) return null;
  return (
    <div>
      {title && (
        <div style={{
          fontSize: "10px", fontWeight: 800, color: "var(--tc-text-muted)",
          textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "10px",
        }}>{title}</div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: "8px" }}>
        {skills.map(s => (
          <div key={s.id} style={{
            padding: "12px",
            borderRadius: "var(--tc-radius-md)",
            background: "var(--tc-neu-inner)",
            boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "6px", flexWrap: "wrap" }}>
              <Crosshair size={12} color="var(--tc-amber)" />
              <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{s.name}</span>
            </div>
            <p style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.5, margin: 0 }}>
              {s.description}
            </p>
            <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "8px" }}>
              <code style={{ background: "var(--tc-input)", padding: "1px 4px" }}>{s.id}</code>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
