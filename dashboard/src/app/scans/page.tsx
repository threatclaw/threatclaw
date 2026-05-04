"use client";

import React, { useEffect, useState, useCallback } from "react";
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

const SCAN_TYPES: ScanType[] = [
  // ── Outils principaux (RSSI standard) ──
  {
    value: "nmap_fingerprint",
    label: "Nmap — découverte réseau",
    description: "Cartographie hôtes actifs, ports ouverts et services. Utile pour repérer les machines inconnues sur ton LAN.",
    target_label: "IP, host ou sous-réseau CIDR",
    target_placeholder: "10.0.0.50  ou  10.0.0.0/24",
    icon: Network,
    color: "#d03020",
    advanced: false,
  },
  {
    value: "trivy_image",
    label: "Trivy — CVE container",
    description: "Scan des CVE (paquets OS et dépendances applicatives) dans une image Docker. Sévérités CRITICAL+HIGH par défaut.",
    target_label: "Image Docker (nom:tag)",
    target_placeholder: "nginx:latest",
    icon: Container,
    color: "#3080d0",
    advanced: false,
  },
  {
    value: "lynis_audit",
    label: "Lynis — hardening Linux",
    description: "Audit de durcissement d'un serveur Linux. Détecte permissions laxistes, services exposés, paramètres SSH/sudo non conformes.",
    target_label: "Cible (laisser vide pour scanner localement)",
    target_placeholder: "/  (système local)",
    icon: Shield,
    color: "#30a050",
    advanced: false,
  },
  {
    value: "docker_bench",
    label: "Docker Bench — CIS",
    description: "CIS Docker Benchmark sur l'hôte ThreatClaw lui-même. Vérifie configuration daemon, isolation containers, gestion images.",
    target_label: "(pas de cible — hôte ThreatClaw)",
    target_placeholder: "n/a",
    icon: Container,
    color: "#9060d0",
    advanced: false,
  },

  // ── Outils avancés (dev / pentest / niche) ──
  {
    value: "syft_sbom",
    label: "Syft — SBOM",
    description: "Génère un Software Bill of Materials (SPDX/CycloneDX) d'une image. Requis NIS2 pour la traçabilité chaîne d'approvisionnement.",
    target_label: "Image Docker ou chemin",
    target_placeholder: "nginx:latest",
    icon: FileText,
    color: "#06b6d4",
    advanced: true,
  },
  {
    value: "semgrep_scan",
    label: "Semgrep — SAST",
    description: "Analyse statique de code pour détecter vulnérabilités, bugs et anti-patterns. Multi-langage (Python, JS, Go, Java, Rust...).",
    target_label: "Chemin du repo git local",
    target_placeholder: "/srv/repos/mon-app",
    icon: Code,
    color: "#d09020",
    advanced: true,
  },
  {
    value: "checkov_scan",
    label: "Checkov — IaC",
    description: "Scan de configurations Infrastructure-as-Code (Terraform, CloudFormation, Kubernetes, ARM). Détecte mauvaises configs sécurité.",
    target_label: "Chemin du dossier IaC",
    target_placeholder: "/srv/repos/terraform",
    icon: Code,
    color: "#06b6d4",
    advanced: true,
  },
  {
    value: "trufflehog_scan",
    label: "TruffleHog — secrets",
    description: "Scan d'un repo git pour détecter clés API, tokens, mots de passe hardcodés (y compris dans l'historique git).",
    target_label: "Chemin du repo git",
    target_placeholder: "/srv/repos/mon-app",
    icon: Key,
    color: "#e84040",
    advanced: true,
  },
  {
    value: "zap_scan",
    label: "OWASP ZAP — DAST",
    description: "Scan dynamique d'une application web (mode baseline). ⚠️ Peut générer du trafic visible et exécuter des actions sur l'app cible.",
    target_label: "URL HTTP/HTTPS",
    target_placeholder: "https://example.com",
    icon: Globe,
    color: "#ff6020",
    advanced: true,
  },
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
  const [selected, setSelected] = useState<ScanType | null>(null);
  const [target, setTarget] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const principal = SCAN_TYPES.filter(t => !t.advanced);
  const advanced = SCAN_TYPES.filter(t => t.advanced);

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
            Choisis un type de scan. Les outils <strong>principaux</strong> couvrent le quotidien sécurité ;
            les <strong>avancés</strong> servent surtout pour audits ponctuels, équipes dev ou pentests.
          </p>

          <SectionTitle title="Outils principaux" />
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
              {showAdvanced ? "▾" : "▸"} Outils avancés ({advanced.length})
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
            ← Retour
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
                }}>avancé</span>
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
              {busy ? <><Loader2 size={12} className="animate-spin" /> Lancement...</> : <><Play size={12} /> Lancer le scan</>}
            </button>

            <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "10px", lineHeight: 1.5 }}>
              Le scan tourne en arrière-plan. Suis sa progression dans l&apos;onglet <strong>Historique</strong>.
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

const DOW = ["Lundi", "Mardi", "Mercredi", "Jeudi", "Vendredi", "Samedi", "Dimanche"];

function describeSchedule(s: Schedule): string {
  const hh = String(s.hour ?? 0).padStart(2, "0");
  const mm = String(s.minute).padStart(2, "0");
  switch (s.frequency) {
    case "hourly":
      return `Toutes les heures à :${mm}`;
    case "daily":
      return `Chaque jour à ${hh}:${mm}`;
    case "weekly":
      return `Chaque ${DOW[s.day_of_week ?? 0]} à ${hh}:${mm}`;
    case "monthly":
      return `Le ${s.day_of_month ?? 1} de chaque mois à ${hh}:${mm}`;
    default:
      return s.frequency;
  }
}

function ScheduledTab() {
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
    if (!confirm("Supprimer cette planification ?")) return;
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
          {schedules.length} planification{schedules.length > 1 ? "s" : ""}
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="tc-btn-embossed"
          style={{ fontSize: "11px", padding: "6px 14px" }}
        >
          {showForm ? <>− Masquer le formulaire</> : <><Bell size={12} /> Nouvelle planification</>}
        </button>
      </div>

      {showForm && <NewScheduleForm onCreated={() => { setShowForm(false); load(); }} />}

      {loading && <div style={{ textAlign: "center", padding: "30px", color: "var(--tc-text-muted)", fontSize: "11px" }}>Chargement...</div>}
      {!loading && schedules.length === 0 && !showForm && (
        <div style={{
          padding: "20px", borderRadius: "var(--tc-radius-md)",
          background: "var(--tc-neu-inner)",
          boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
        }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "6px" }}>Aucune planification pour le moment</div>
          <div style={{ fontSize: "11px", color: "var(--tc-text-sec)", lineHeight: 1.6 }}>
            ThreatClaw fingerprinte déjà chaque nouvel asset automatiquement (Nmap, TTL 1h).
            Utilise les planifications pour des scans récurrents type "Trivy hebdo sur image
            de prod" ou "Lynis mensuel sur l&apos;hôte".
          </div>
        </div>
      )}
      {!loading && schedules.length > 0 && (
        <div style={{ borderRadius: "var(--tc-radius-md)", overflow: "hidden", border: "1px solid var(--tc-border)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
            <thead>
              <tr style={{ background: "var(--tc-surface-alt)", textAlign: "left", color: "var(--tc-text-muted)", fontSize: "9px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                <th style={{ padding: "10px 12px" }}>Nom</th>
                <th style={{ padding: "10px 12px" }}>Type</th>
                <th style={{ padding: "10px 12px" }}>Cible</th>
                <th style={{ padding: "10px 12px" }}>Fréquence</th>
                <th style={{ padding: "10px 12px" }}>Prochain</th>
                <th style={{ padding: "10px 12px" }}>Statut</th>
                <th style={{ padding: "10px 12px", textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {schedules.map((s) => (
                <tr key={s.id} style={{ borderTop: "1px solid var(--tc-border)" }}>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)" }}>{s.name || `Sans nom`}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace" }}>{s.scan_type}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text)", fontFamily: "'JetBrains Mono', monospace", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis" }}>{s.target}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-sec)" }}>{describeSchedule(s)}</td>
                  <td style={{ padding: "8px 12px", color: "var(--tc-text-muted)" }}>{relTime(s.next_run_at)}</td>
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
                      {s.enabled ? "Actif" : "En pause"}
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
                    >Supprimer</button>
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

function NewScheduleForm({ onCreated }: { onCreated: () => void }) {
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
      setErr("Cible requise");
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

  const selectedType = SCAN_TYPES.find(t => t.value === scanType) || SCAN_TYPES[0];

  return (
    <div style={{
      marginBottom: "16px", padding: "16px",
      background: "var(--tc-neu-inner)",
      boxShadow: "inset 0 2px 6px rgba(0,0,0,0.25), inset 0 1px 2px rgba(0,0,0,0.2), 0 1px 0 rgba(255,255,255,0.08)",
      borderRadius: "var(--tc-radius-md)",
    }}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Nom (optionnel)</label>
          <input
            type="text" value={name} onChange={(e) => setName(e.target.value)}
            placeholder="ex: Trivy hebdo image prod"
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          />
        </div>
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Type de scan</label>
          <select
            value={scanType} onChange={(e) => setScanType(e.target.value)}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          >
            {SCAN_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}{t.advanced ? " · avancé" : ""}</option>)}
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
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Fréquence</label>
          <select
            value={frequency} onChange={(e) => setFrequency(e.target.value as any)}
            style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
          >
            <option value="hourly">Toutes les heures</option>
            <option value="daily">Chaque jour</option>
            <option value="weekly">Chaque semaine</option>
            <option value="monthly">Chaque mois</option>
          </select>
        </div>
        {frequency === "weekly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Jour</label>
            <select
              value={dayOfWeek} onChange={(e) => setDayOfWeek(parseInt(e.target.value))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            >
              {DOW.map((d, i) => <option key={i} value={i}>{d}</option>)}
            </select>
          </div>
        )}
        {frequency === "monthly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Jour du mois (1-28)</label>
            <input
              type="number" min={1} max={28} value={dayOfMonth} onChange={(e) => setDayOfMonth(parseInt(e.target.value || "1"))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            />
          </div>
        )}
        {frequency !== "hourly" && (
          <div>
            <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Heure (0-23)</label>
            <input
              type="number" min={0} max={23} value={hour} onChange={(e) => setHour(parseInt(e.target.value || "0"))}
              style={{ width: "100%", padding: "7px 10px", fontSize: "11px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-input)", color: "var(--tc-text)", outline: "none" }}
            />
          </div>
        )}
        <div>
          <label style={{ fontSize: "10px", color: "var(--tc-text-muted)", display: "block", marginBottom: "4px" }}>Minute (0-59)</label>
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
        {busy ? <><Loader2 size={12} className="animate-spin" /> Création...</> : <><Bell size={12} /> Créer la planification</>}
      </button>
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
                Niche / pentesting / CI-CD — sortis du parcours sécurité standard mais conservés pour les usages
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
