"use client";

import React, { useEffect, useState, useCallback } from "react";
import { useLocale } from "@/lib/useLocale";
import {
  Play, Clock, Bell, Puzzle, RefreshCw, CheckCircle2, X, Loader2,
  Search, AlertTriangle, Crosshair,
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

const SCAN_TYPES = [
  { value: "nmap_fingerprint", label: "Nmap (fingerprint)", target_label: "IP / sous-réseau", target_placeholder: "10.0.0.50 ou 10.0.0.0/24" },
  { value: "trivy_image", label: "Trivy (CVE container)", target_label: "Image Docker", target_placeholder: "nginx:latest" },
];

function formatDuration(ms: number | null): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m${Math.floor((ms % 60_000) / 1000)}s`;
}

function relTime(iso: string | null): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const diff = Date.now() - t;
  if (diff < 60_000) return "à l'instant";
  if (diff < 3_600_000) return `il y a ${Math.floor(diff / 60_000)} min`;
  if (diff < 86_400_000) return `il y a ${Math.floor(diff / 3_600_000)} h`;
  return new Date(iso).toLocaleString("fr-FR");
}

function statusPill(status: string) {
  const colors: Record<string, { bg: string; fg: string; border: string; label: string }> = {
    queued: { bg: "rgba(208,144,32,0.10)", fg: "#d09020", border: "rgba(208,144,32,0.25)", label: "en attente" },
    running: { bg: "rgba(48,128,208,0.10)", fg: "#3080d0", border: "rgba(48,128,208,0.25)", label: "en cours" },
    done: { bg: "rgba(48,160,80,0.10)", fg: "#30a050", border: "rgba(48,160,80,0.25)", label: "terminé" },
    error: { bg: "rgba(208,48,32,0.10)", fg: "#d03020", border: "rgba(208,48,32,0.25)", label: "erreur" },
    skipped: { bg: "rgba(140,140,140,0.10)", fg: "var(--tc-text-muted)", border: "rgba(140,140,140,0.25)", label: "ignoré" },
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
            {tab === "launch" && "lancer un scan"}
            {tab === "history" && "historique"}
            {tab === "scheduled" && "planifiés"}
            {tab === "library" && "bibliothèque"}
          </span>
        </h1>
      </div>

      {tab === "launch" && <LaunchTab locale={locale} />}
      {tab === "history" && <HistoryTab />}
      {tab === "scheduled" && <ScheduledTab />}
      {tab === "library" && <LibraryTab locale={locale} />}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function LaunchTab({ locale: _ }: { locale: "fr" | "en" }) {
  const [scanType, setScanType] = useState<string>(SCAN_TYPES[0].value);
  const [target, setTarget] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);

  const launch = async () => {
    if (!target.trim()) return;
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch("/api/tc/scans/queue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), scan_type: scanType, ttl_seconds: 0 }),
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

  const current = SCAN_TYPES.find(t => t.value === scanType) || SCAN_TYPES[0];

  return (
    <div style={{ maxWidth: "640px" }}>
      <div style={{
        background: "var(--tc-neu-inner)",
        boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
        borderRadius: "var(--tc-radius-md)",
        padding: "20px",
      }}>
        <div style={{ marginBottom: "14px" }}>
          <label style={{ fontSize: "11px", color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
            Type de scan
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            style={{
              width: "100%", padding: "9px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
            }}
          >
            {SCAN_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
          </select>
        </div>

        <div style={{ marginBottom: "14px" }}>
          <label style={{ fontSize: "11px", color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
            {current.target_label}
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={current.target_placeholder}
            style={{
              width: "100%", padding: "9px 12px", borderRadius: "var(--tc-radius-input)", fontSize: "12px",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", outline: "none",
            }}
          />
        </div>

        <button
          onClick={launch}
          disabled={busy || !target.trim()}
          className="tc-btn-embossed"
          style={{ fontSize: "11px", padding: "10px 20px", width: "100%", justifyContent: "center" }}
        >
          {busy ? <><Loader2 size={12} className="animate-spin" /> Lancement...</> : <><Play size={12} /> Lancer le scan</>}
        </button>

        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "10px", lineHeight: 1.5 }}>
          Le scan part en arrière-plan. Suivez sa progression dans l'onglet <strong>Historique</strong>.
          Les résultats enrichissent automatiquement les assets et findings.
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
                <div style={{ fontSize: "12px", fontWeight: 700, color: "#d03020" }}>Échec</div>
                <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", marginTop: "3px" }}>{result.error}</div>
              </div>
            </div>
          ) : result.queued ? (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <CheckCircle2 size={14} color="#30a050" />
              <div style={{ fontSize: "12px", color: "var(--tc-text-sec)" }}>
                Scan #{result.scan_id} mis en file. Voir <a href="/scans?tab=history" style={{ color: "var(--tc-blue)" }}>Historique</a>.
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <AlertTriangle size={14} color="var(--tc-amber)" />
              <div style={{ fontSize: "12px", color: "var(--tc-text-sec)" }}>{result.reason || "Scan ignoré (déjà fait récemment)"}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function HistoryTab() {
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
          <option value="">Tous statuts</option>
          <option value="queued">En attente</option>
          <option value="running">En cours</option>
          <option value="done">Terminés</option>
          <option value="error">Erreurs</option>
        </select>
        <button onClick={load} className="tc-btn-embossed" style={{ fontSize: "11px", padding: "6px 12px" }}>
          <RefreshCw size={12} /> Actualiser
        </button>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>Chargement...</div>}
      {!loading && scans.length === 0 && (
        <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>
          Aucun scan {statusFilter ? `avec statut "${statusFilter}"` : "pour le moment"}.
        </div>
      )}
      {!loading && scans.length > 0 && (
        <div style={{ borderRadius: "var(--tc-radius-md)", overflow: "hidden", border: "1px solid var(--tc-border)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", textAlign: "left", color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                <th style={{ padding: "10px 12px" }}>Type</th>
                <th style={{ padding: "10px 12px" }}>Cible</th>
                <th style={{ padding: "10px 12px" }}>Statut</th>
                <th style={{ padding: "10px 12px" }}>Durée</th>
                <th style={{ padding: "10px 12px" }}>Quand</th>
                <th style={{ padding: "10px 12px" }}>Origine</th>
                <th style={{ padding: "10px 12px" }}>Résultat</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr key={s.id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace" }}>{s.scan_type}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis" }}>{s.target}</td>
                  <td style={{ padding: "8px 12px" }}>{statusPill(s.status)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{formatDuration(s.duration_ms)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{relTime(s.requested_at)}</td>
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
function ScheduledTab() {
  return (
    <div style={{
      maxWidth: "640px", padding: "20px",
      background: "var(--tc-neu-inner)",
      boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
      borderRadius: "var(--tc-radius-md)",
    }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
        <Bell size={16} color="var(--tc-text-muted)" style={{ flexShrink: 0, marginTop: "2px" }} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "6px" }}>Aucun scan planifié</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.6 }}>
            Aujourd'hui, ThreatClaw déclenche les scans automatiquement à chaque nouvel asset détecté
            (Nmap fingerprint, TTL 1h). Pour planifier un scan récurrent (hebdomadaire, mensuel),
            cette interface arrivera dans une prochaine version.
            <br /><br />
            En attendant : scan ponctuel via l'onglet <strong>Lancer</strong> ou via la carte
            "Surface" sur la page d'un asset (bouton Re-scanner).
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────
function LibraryTab({ locale: _ }: { locale: "fr" | "en" }) {
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
        Outils de scan disponibles. Les scans courants sont déclenchés automatiquement par ThreatClaw
        à chaque nouvel asset / image découvert. Cette page liste l'inventaire complet pour référence.
      </p>

      <SkillSection title="Outils principaux" skills={core} />

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
            {showAdvanced ? "▾" : "▸"} Outils avancés ({advanced.length})
          </button>
          {showAdvanced && (
            <div style={{ marginTop: "12px" }}>
              <p style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginBottom: "10px", fontStyle: "italic" }}>
                Niche / pentesting / CI-CD — sortis du parcours RSSI standard mais conservés pour les usages
                avancés (équipes dev, MSP, audits ponctuels).
              </p>
              <SkillSection title="" skills={advanced} />
            </div>
          )}
        </div>
      )}

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>Chargement...</div>}
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
