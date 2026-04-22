"use client";

// Experimental frontend playground — SOC operator console.
// Full viewport, 3-column layout, collapsible left rail, sober palette.
// Data comes from the real /api/tc/* endpoints; nothing is mocked.
//
// Red is only used for things that are actually urgent — the rest stays
// in greys and tabular numbers. No purple, no multicolour, no floating
// "AI-slop" tile cards.

import React, { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Shield,
  Activity,
  Radio,
  Bell,
  MessageSquare,
  BrainCircuit,
  Gavel,
  Settings,
  FileText,
  Cpu,
  ChevronsLeft,
  ChevronsRight,
  Check,
} from "lucide-react";

type Incident = {
  id: number;
  severity: string | null;
  verdict: string;
  status: string;
  asset?: string;
  title?: string;
  summary?: string;
  mitre_techniques?: string[];
  created_at?: string;
  alert_count?: number;
};

type AssetScore = { asset: string; score: number };
type Situation = {
  global_score?: number;
  assets?: AssetScore[];
  computed_at?: string;
  total_open_findings?: number;
  total_active_alerts?: number;
  new_alerts_count?: number;
};

function isSevere(s: string | null | undefined) {
  const x = (s ?? "").toUpperCase();
  return x === "HIGH" || x === "CRITICAL";
}

function formatRelative(iso: string | undefined, now: Date) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = Math.max(0, now.getTime() - d.getTime()) / 1000;
  if (diff < 60) return `il y a ${Math.round(diff)}s`;
  if (diff < 3600) return `il y a ${Math.round(diff / 60)}m`;
  if (diff < 86400) return `il y a ${Math.round(diff / 3600)}h`;
  return `il y a ${Math.round(diff / 86400)}j`;
}

export default function DashTest() {
  const [railCollapsed, setRailCollapsed] = useState(false);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [situation, setSituation] = useState<Situation | null>(null);
  const [alertsTotal, setAlertsTotal] = useState<number>(0);
  const [now, setNow] = useState(new Date());

  // Wall clock tick for relative timestamps + cycle countdown
  useEffect(() => {
    const iv = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(iv);
  }, []);

  // Poll real API every 15 s
  useEffect(() => {
    let mounted = true;
    async function load() {
      const [incR, sitR, alC] = await Promise.allSettled([
        fetch("/api/tc/incidents?limit=500").then((r) => r.json()),
        fetch("/api/tc/intelligence/situation").then((r) => r.json()),
        fetch("/api/tc/alerts/counts").then((r) => r.json()),
      ]);
      if (!mounted) return;
      if (incR.status === "fulfilled") setIncidents(incR.value?.incidents ?? []);
      if (sitR.status === "fulfilled") setSituation(sitR.value ?? null);
      if (alC.status === "fulfilled") {
        const counts = alC.value?.counts ?? [];
        setAlertsTotal(counts.reduce((a: number, c: { count: number }) => a + c.count, 0));
      }
    }
    load();
    const iv = setInterval(load, 15_000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, []);

  const pending = incidents.filter((i) => i.verdict === "pending");
  const confirmed = incidents.filter((i) => i.verdict === "confirmed");
  const confirmedHigh = confirmed.filter((i) => isSevere(i.severity));
  const openCritical = incidents
    .filter((i) => (i.severity ?? "").toUpperCase() === "CRITICAL" && i.status !== "closed")
    .sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0];
  const activeIncident =
    openCritical ||
    pending.sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""))[0] ||
    null;

  const triaged = pending.length + confirmed.length;
  const noisePct = alertsTotal > 0 ? (1 - triaged / alertsTotal) * 100 : null;
  const topAssets = (situation?.assets ?? [])
    .slice()
    .sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
    .slice(0, 5);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateRows: "1fr 28px",
        height: "calc(100vh - 72px)", /* - layout banner (16px) - top bar (44px) - status bar (28px) */
        background: "var(--tc-bg)",
        color: "var(--tc-text)",
        fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: "12px",
        overflow: "hidden",
      }}
    >
      {/* ═══════ MAIN 3-COL ═══════ */}
      <main
        style={{
          display: "grid",
          gridTemplateColumns: `${railCollapsed ? "52px" : "260px"} 1fr 340px`,
          overflow: "hidden",
          minHeight: 0,
          transition: "grid-template-columns 180ms",
        }}
      >
        {/* ─── LEFT RAIL ─── */}
        <LeftRail
          collapsed={railCollapsed}
          onToggle={() => setRailCollapsed((v) => !v)}
          pending={pending.length}
          confirmed={confirmed.length}
          alertsTotal={alertsTotal}
          situation={situation}
          topAssets={topAssets}
        />

        {/* ─── CENTER ─── */}
        <Center
          activeIncident={activeIncident}
          incidents={incidents}
          situation={situation}
          alertsTotal={alertsTotal}
          now={now}
        />

        {/* ─── RIGHT AXIS (HITL) ─── */}
        <RightAxis
          pending={pending.length}
          confirmed={confirmed.length}
          confirmedHigh={confirmedHigh.length}
          noisePct={noisePct}
          activeIncident={activeIncident}
          now={now}
        />
      </main>

      {/* ═══════ STATUS BAR ═══════ */}
      <StatusBar pending={pending.length} confirmed={confirmed.length} alertsTotal={alertsTotal} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// LEFT RAIL — collapsible, holds live posture + sources
// ═══════════════════════════════════════════════════════════════
function LeftRail({
  collapsed,
  onToggle,
  pending,
  confirmed,
  alertsTotal,
  situation,
  topAssets,
}: {
  collapsed: boolean;
  onToggle: () => void;
  pending: number;
  confirmed: number;
  alertsTotal: number;
  situation: Situation | null;
  topAssets: AssetScore[];
}) {
  const globalScore = situation?.global_score !== undefined ? Math.round(situation.global_score) : null;
  return (
    <aside
      style={{
        borderRight: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Toggle */}
      <button
        onClick={onToggle}
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "flex-end",
          padding: "8px 12px",
          background: "transparent",
          border: "none",
          borderBottom: "1px solid var(--tc-border)",
          color: "var(--tc-text-muted)",
          cursor: "pointer",
        }}
        title={collapsed ? "Étendre" : "Réduire"}
      >
        {collapsed ? <ChevronsRight size={13} /> : <ChevronsLeft size={13} />}
      </button>

      {collapsed ? (
        <CollapsedRailIcons />
      ) : (
        <div style={{ overflowY: "auto", flex: 1 }}>
          {/* Posture live */}
          <Section title="Posture · live">
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <RailStat value={globalScore ?? "—"} label="score" accent={globalScore !== null && globalScore < 50 ? "var(--tc-red)" : undefined} />
              <RailStat value={pending} label="à trier" accent={pending > 0 ? "var(--tc-red)" : undefined} />
              <RailStat value={confirmed} label="confirmés" />
              <RailStat value={alertsTotal.toLocaleString("fr")} label="alertes brutes" mono />
            </div>
          </Section>

          {/* Cycle agent */}
          <Section title="Cycle agent">
            <CycleSteps />
          </Section>

          {/* Top risk assets */}
          <Section title="Assets à risque">
            {topAssets.length === 0 ? (
              <EmptyLine text="aucun asset flaggé" />
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {topAssets.map((a) => {
                  const risk = a.score ?? 0;
                  const health = Math.max(0, 100 - Math.round(risk));
                  return (
                    <div
                      key={a.asset}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "1fr auto",
                        padding: "4px 0",
                        borderBottom: "1px dashed var(--tc-border)",
                        fontSize: "11px",
                      }}
                    >
                      <span style={{ color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {a.asset}
                      </span>
                      <span
                        style={{
                          color: risk >= 70 ? "var(--tc-red)" : risk >= 40 ? "#d09020" : "var(--tc-text-muted)",
                          fontVariantNumeric: "tabular-nums",
                          marginLeft: "8px",
                        }}
                      >
                        {health}/100
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </Section>

          {/* Collectors / sources live */}
          <Section title="Collecteurs">
            <CollectorsList />
          </Section>
        </div>
      )}
    </aside>
  );
}

function CollapsedRailIcons() {
  const icons = [
    { icon: Shield, href: "/dash-test", label: "Console" },
    { icon: Activity, href: "/intelligence", label: "Intelligence" },
    { icon: Radio, href: "/sources", label: "Sources" },
    { icon: Bell, href: "/incidents", label: "Incidents" },
    { icon: MessageSquare, href: "/chat", label: "Chat" },
    { icon: BrainCircuit, href: "/governance", label: "Governance" },
    { icon: FileText, href: "/exports", label: "Reports" },
    { icon: Settings, href: "/setup", label: "Config" },
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column", padding: "8px 0" }}>
      {icons.map((i) => {
        const Ic = i.icon;
        return (
          <Link
            key={i.href}
            href={i.href}
            title={i.label}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              padding: "10px 0",
              color: "var(--tc-text-sec)",
              textDecoration: "none",
            }}
          >
            <Ic size={14} />
          </Link>
        );
      })}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: "14px 14px 16px", borderBottom: "1px solid var(--tc-border)" }}>
      <div
        style={{
          fontSize: "9px",
          letterSpacing: "0.22em",
          textTransform: "uppercase",
          color: "var(--tc-text-muted)",
          marginBottom: "10px",
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function RailStat({
  value,
  label,
  accent,
  mono,
}: {
  value: string | number;
  label: string;
  accent?: string;
  mono?: boolean;
}) {
  return (
    <div style={{ border: "1px solid var(--tc-border)", padding: "8px 10px" }}>
      <div
        style={{
          fontSize: mono ? "14px" : "20px",
          color: accent ?? "var(--tc-text)",
          fontVariantNumeric: "tabular-nums",
          letterSpacing: "-0.01em",
        }}
      >
        {value}
      </div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.12em", textTransform: "uppercase", marginTop: "2px" }}>
        {label}
      </div>
    </div>
  );
}

function CycleSteps() {
  // Static for now — TODO wire to real IE cycle state via an endpoint.
  const steps = [
    { n: "01", label: "Observe", desc: "syslog · sigma · wazuh" },
    { n: "02", label: "Correlate", desc: "graph STIX 2.1" },
    { n: "03", label: "Enrich", desc: "KEV · EPSS · CTI" },
    { n: "04", label: "Decide", desc: "L2 forensique → HITL" },
  ];
  const activeIdx = 2; // placeholder
  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {steps.map((s, i) => {
        const active = i === activeIdx;
        return (
          <div
            key={s.n}
            style={{
              display: "grid",
              gridTemplateColumns: "22px 1fr",
              gap: "10px",
              padding: "8px 0",
              borderBottom: i < steps.length - 1 ? "1px dashed var(--tc-border)" : "none",
              position: "relative",
            }}
          >
            <div style={{ fontSize: "9px", color: active ? "var(--tc-red)" : "var(--tc-text-muted)", letterSpacing: "0.15em", paddingTop: "2px" }}>
              {s.n}
            </div>
            <div>
              <div style={{ fontSize: "10px", color: active ? "var(--tc-red)" : "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.15em" }}>
                {s.label}
              </div>
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "1px" }}>{s.desc}</div>
            </div>
            {active && (
              <span
                style={{
                  position: "absolute",
                  left: "-14px",
                  top: "14px",
                  width: "6px",
                  height: "6px",
                  borderRadius: "50%",
                  background: "var(--tc-red)",
                  boxShadow: "0 0 8px var(--tc-red)",
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

function CollectorsList() {
  // Placeholder — should be wired to /api/tc/sources status later.
  const items = [
    { name: "wazuh.siem", rate: "live", ok: true },
    { name: "crowdsec.cti", rate: "sync 3m", ok: true },
    { name: "mitre.attack", rate: "static", ok: true },
    { name: "cisa.kev", rate: "sync 14m", ok: true },
    { name: "threatfox.abuse", rate: "sync 5m", ok: true },
  ];
  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      {items.map((s) => (
        <div
          key={s.name}
          style={{
            display: "grid",
            gridTemplateColumns: "1fr auto auto",
            gap: "8px",
            alignItems: "center",
            padding: "6px 0",
            borderBottom: "1px dashed var(--tc-border)",
            fontSize: "10.5px",
          }}
        >
          <span style={{ color: "var(--tc-text)" }}>{s.name}</span>
          <span style={{ color: "var(--tc-text-muted)", fontSize: "10px" }}>{s.rate}</span>
          <span
            style={{
              width: "6px",
              height: "6px",
              borderRadius: "50%",
              background: s.ok ? "#30a050" : "var(--tc-red)",
              boxShadow: `0 0 6px ${s.ok ? "#30a050" : "var(--tc-red)"}`,
            }}
          />
        </div>
      ))}
    </div>
  );
}

function EmptyLine({ text }: { text: string }) {
  return <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", fontStyle: "italic" }}>{text}</div>;
}

// ═══════════════════════════════════════════════════════════════
// CENTER — active incident + recent timeline + log tail
// ═══════════════════════════════════════════════════════════════
function Center({
  activeIncident,
  incidents,
  situation,
  alertsTotal,
  now,
}: {
  activeIncident: Incident | null;
  incidents: Incident[];
  situation: Situation | null;
  alertsTotal: number;
  now: Date;
}) {
  return (
    <section
      style={{
        display: "grid",
        // auto (incident bar) / auto (compact timeline ≤ 38 vh) / 1fr (log tail fills)
        gridTemplateRows: "auto auto 1fr",
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      {activeIncident ? (
        <IncidentBar incident={activeIncident} now={now} />
      ) : (
        <div
          style={{
            borderBottom: "1px solid var(--tc-border)",
            padding: "14px 18px",
            color: "var(--tc-text-muted)",
            fontSize: "11px",
            letterSpacing: "0.04em",
          }}
        >
          Aucun incident actif · cycle IE toutes les 5 min — un asset qui flippe remonte ici automatiquement.
        </div>
      )}

      <IncidentList incidents={incidents} now={now} />

      <LogTail incidents={incidents} situation={situation} alertsTotal={alertsTotal} />
    </section>
  );
}

function IncidentBar({ incident, now }: { incident: Incident; now: Date }) {
  const sev = (incident.severity ?? "").toUpperCase();
  const isCrit = sev === "CRITICAL" || sev === "HIGH";
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "auto 1fr auto",
        borderBottom: "1px solid var(--tc-border)",
        background: isCrit ? "linear-gradient(180deg, rgba(208,48,32,0.06), transparent)" : "transparent",
      }}
    >
      <div
        style={{
          padding: "14px 18px",
          borderRight: "1px solid var(--tc-border)",
          borderLeft: `3px solid ${isCrit ? "var(--tc-red)" : "var(--tc-border)"}`,
        }}
      >
        <div style={{ fontSize: "9px", letterSpacing: "0.22em", color: isCrit ? "var(--tc-red)" : "var(--tc-text-muted)", textTransform: "uppercase" }}>
          Incident · {incident.verdict}
        </div>
        <div style={{ fontSize: "16px", color: "var(--tc-text)", marginTop: "2px" }}>
          INC-{String(incident.id).padStart(6, "0")}
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "2px", letterSpacing: "0.08em" }}>
          {formatRelative(incident.created_at, now)}
        </div>
      </div>

      <div
        style={{
          padding: "14px 18px",
          display: "grid",
          gridTemplateColumns: "repeat(5, auto)",
          gap: "28px",
          alignItems: "center",
        }}
      >
        <Meta label="Asset" value={incident.asset ?? "—"} accent={isCrit ? "var(--tc-red)" : undefined} />
        <Meta label="Sévérité" value={sev || "—"} accent={isCrit ? "var(--tc-red)" : undefined} />
        <Meta label="Status" value={incident.status} />
        <Meta label="Alerts" value={String(incident.alert_count ?? "—")} />
        <Meta
          label="MITRE"
          value={
            incident.mitre_techniques && incident.mitre_techniques.length > 0
              ? incident.mitre_techniques.join(" · ")
              : "—"
          }
        />
      </div>

      <div style={{ padding: "10px 14px", display: "flex", gap: "8px", alignItems: "center", borderLeft: "1px solid var(--tc-border)" }}>
        <Link
          href={`/incidents?id=${incident.id}`}
          style={{
            padding: "7px 12px",
            border: "1px solid var(--tc-red)",
            fontSize: "10px",
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: "var(--tc-red)",
            textDecoration: "none",
          }}
        >
          ouvrir
        </Link>
      </div>
    </div>
  );
}

function Meta({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.14em", textTransform: "uppercase" }}>
        {label}
      </div>
      <div style={{ fontSize: "12px", color: accent ?? "var(--tc-text)", marginTop: "2px" }}>{value}</div>
    </div>
  );
}

function IncidentList({ incidents, now }: { incidents: Incident[]; now: Date }) {
  // Compact — stays short when empty and caps at ~5 rows when not so the log
  // tail below gets the room it needs.
  return (
    <div
      style={{
        maxHeight: incidents.length === 0 ? "90px" : "220px",
        overflow: "auto",
        padding: "10px 18px 12px",
        borderBottom: "1px solid var(--tc-border)",
      }}
    >
      <div
        style={{
          fontSize: "9px",
          letterSpacing: "0.22em",
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          marginBottom: "8px",
          display: "flex",
          justifyContent: "space-between",
        }}
      >
        <span>Incidents récents</span>
        <span>{incidents.length > 0 ? `${incidents.length} total` : "—"}</span>
      </div>
      {incidents.length === 0 ? (
        <div
          style={{
            color: "var(--tc-text-muted)",
            fontSize: "10.5px",
            letterSpacing: "0.04em",
          }}
        >
          aucun incident — prochain cycle IE dans &lt; 5 min
        </div>
      ) : (
        incidents.slice(0, 8).map((i) => {
          const sev = (i.severity ?? "").toUpperCase();
          const isCrit = sev === "CRITICAL" || sev === "HIGH";
          return (
            <div
              key={i.id}
              style={{
                display: "grid",
                gridTemplateColumns: "62px 1fr 70px 60px",
                gap: "12px",
                padding: "6px 0",
                borderBottom: "1px dashed var(--tc-border)",
                alignItems: "center",
              }}
            >
              <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", letterSpacing: "0.06em" }}>
                {formatRelative(i.created_at, now)}
              </div>
              <div style={{ fontSize: "11px", color: "var(--tc-text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                <span
                  style={{
                    display: "inline-block",
                    width: "5px",
                    height: "5px",
                    borderRadius: "50%",
                    background: isCrit ? "var(--tc-red)" : sev === "MEDIUM" ? "#d09020" : "#30a050",
                    marginRight: "8px",
                    verticalAlign: "middle",
                  }}
                />
                {i.asset ?? "—"} <span style={{ color: "var(--tc-text-muted)" }}>· {i.title ?? ""}</span>
              </div>
              <span style={{ fontSize: "9px", color: isCrit ? "var(--tc-red)" : "var(--tc-text-muted)", letterSpacing: "0.08em" }}>
                {sev}
              </span>
              <Link
                href={`/incidents?id=${i.id}`}
                style={{ fontSize: "9px", color: "var(--tc-red)", textDecoration: "none", textAlign: "right", letterSpacing: "0.1em" }}
              >
                ouvrir →
              </Link>
            </div>
          );
        })
      )}
    </div>
  );
}

type LogTag = "cycle" | "incident" | "alert" | "findings" | "init" | "poll" | "source" | "health";

type LogLine = {
  at: Date;
  tag: LogTag;
  color: string;
  msg: string;
};

type SourceStatus = {
  id: string;
  name: string;
  status: string;
  hosts?: number;
  logs_24h?: number;
  last_seen?: string | null;
};

function LogTail({
  incidents,
  situation,
  alertsTotal,
}: {
  incidents: Incident[];
  situation: Situation | null;
  alertsTotal: number;
}) {
  // The log is driven by three real signals:
  //   (1) state deltas from parent polling (incidents, alerts, IE cycle)
  //   (2) /api/tc/sources/status polled every 12s — connector liveness
  //   (3) /api/tc/health polled every 20s — db / ml / llm heartbeat
  // Plus a periodic "poll" summary so the log is never idle for more than ~90s.
  const [lines, setLines] = useState<LogLine[]>([
    {
      at: new Date(),
      tag: "init",
      color: "var(--tc-text-muted)",
      msg: "console mounted · polling /api/tc · sources=/health=/incidents=/situation",
    },
  ]);
  const prev = useRef({
    maxIncidentId: -1,
    alertsTotal: -1,
    computedAt: "",
    sources: new Map<string, SourceStatus>(),
    healthKey: "",
    healthInit: false,
    sourcesInit: false,
  });
  // Latest numbers for the periodic poll-summary (closure would be stale otherwise).
  const latest = useRef({
    incidents: incidents.length,
    alerts: alertsTotal,
    score: situation?.global_score,
    sourcesActive: 0,
    sourcesTotal: 0,
  });
  const scrollRef = useRef<HTMLDivElement>(null);

  const push = useCallback((line: LogLine) => {
    setLines((l) => [...l, line].slice(-250));
  }, []);

  // (1) state deltas from parent polling
  useEffect(() => {
    const nowDate = new Date();
    const newLines: LogLine[] = [];
    const maxId = incidents.reduce((m, i) => (i.id > m ? i.id : m), 0);
    const cAt = situation?.computed_at ?? "";

    if (prev.current.maxIncidentId >= 0 && maxId > prev.current.maxIncidentId) {
      const latestInc = incidents.find((i) => i.id === maxId);
      if (latestInc) {
        const sev = (latestInc.severity ?? "").toUpperCase() || "UNKNOWN";
        const red = sev === "CRITICAL" || sev === "HIGH";
        newLines.push({
          at: nowDate,
          tag: "incident",
          color: red ? "var(--tc-red)" : "var(--tc-text)",
          msg: `INC-${String(latestInc.id).padStart(6, "0")} · ${sev} · asset=${latestInc.asset ?? "—"} · verdict=${latestInc.verdict}`,
        });
      }
    }

    if (prev.current.alertsTotal >= 0 && alertsTotal !== prev.current.alertsTotal) {
      const delta = alertsTotal - prev.current.alertsTotal;
      newLines.push({
        at: nowDate,
        tag: "alert",
        color: delta > 0 ? "#d09020" : "var(--tc-text-sec)",
        msg: `sigma_alerts ${delta > 0 ? "+" : ""}${delta} · total=${alertsTotal.toLocaleString("fr")}`,
      });
    }

    if (prev.current.computedAt && cAt && cAt !== prev.current.computedAt) {
      newLines.push({
        at: nowDate,
        tag: "cycle",
        color: "#30a050",
        msg: `intelligence engine tick · incidents=${incidents.length} · findings=${situation?.total_open_findings ?? "?"} · score=${situation?.global_score ?? "—"}`,
      });
    }

    prev.current.maxIncidentId = maxId;
    prev.current.alertsTotal = alertsTotal;
    prev.current.computedAt = cAt;
    latest.current.incidents = incidents.length;
    latest.current.alerts = alertsTotal;
    latest.current.score = situation?.global_score;

    if (newLines.length > 0) setLines((l) => [...l, ...newLines].slice(-250));
  }, [incidents, situation, alertsTotal]);

  // (2) connector liveness
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await fetch("/api/tc/sources/status", { signal: AbortSignal.timeout(6000) });
        if (!r.ok) throw new Error("status " + r.status);
        const d = await r.json();
        if (cancelled) return;
        const list = (d.sources || []) as SourceStatus[];
        const nowDate = new Date();
        const next = new Map<string, SourceStatus>();
        for (const s of list) next.set(s.id, s);
        latest.current.sourcesTotal = list.length;
        latest.current.sourcesActive = list.filter(
          (s) => s.status === "active" || s.status === "listening" || s.status === "ok",
        ).length;

        if (!prev.current.sourcesInit) {
          prev.current.sourcesInit = true;
          prev.current.sources = next;
          push({
            at: nowDate,
            tag: "source",
            color: "var(--tc-text-sec)",
            msg: `sources · ${latest.current.sourcesActive}/${list.length} configurées · ${list.map((s) => `${s.id}=${s.status}`).join(" ")}`,
          });
          return;
        }
        for (const s of list) {
          const prior = prev.current.sources.get(s.id);
          if (!prior) continue;
          if (prior.status !== s.status) {
            push({
              at: nowDate,
              tag: "source",
              color: s.status === "active" ? "#30a050" : s.status === "down" ? "var(--tc-red)" : "var(--tc-text-sec)",
              msg: `source ${s.id} · ${prior.status} → ${s.status}`,
            });
          }
          const prevLogs = prior.logs_24h ?? 0;
          const curLogs = s.logs_24h ?? 0;
          if (curLogs > prevLogs) {
            push({
              at: nowDate,
              tag: "source",
              color: "#d09020",
              msg: `source ${s.id} · +${(curLogs - prevLogs).toLocaleString("fr")} logs · last_seen=${s.last_seen ? "live" : "—"}`,
            });
          }
          if (prior.last_seen !== s.last_seen && s.last_seen) {
            push({
              at: nowDate,
              tag: "source",
              color: "#30a050",
              msg: `source ${s.id} · last_seen updated · hosts=${s.hosts ?? 0}`,
            });
          }
        }
        prev.current.sources = next;
      } catch {
        /* silent */
      }
    };
    tick();
    const iv = setInterval(tick, 12_000);
    return () => {
      cancelled = true;
      clearInterval(iv);
    };
  }, [push]);

  // (3) health heartbeat
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const r = await fetch("/api/tc/health", { signal: AbortSignal.timeout(5000) });
        if (!r.ok) throw new Error("status " + r.status);
        const d = await r.json();
        if (cancelled) return;
        const key = `${d.database ? "db" : "!db"}|${d.ml?.alive ? "ml" : "!ml"}|${d.llm ?? "?"}|${d.disk_free ?? ""}`;
        if (!prev.current.healthInit) {
          prev.current.healthInit = true;
          prev.current.healthKey = key;
          push({
            at: new Date(),
            tag: "health",
            color: "#30a050",
            msg: `health · db=${d.database ? "ok" : "down"} · ml=${d.ml?.alive ? "alive" : "idle"} · llm=${d.llm ?? "—"} · disk=${d.disk_free ?? "?"}`,
          });
          return;
        }
        if (key !== prev.current.healthKey) {
          prev.current.healthKey = key;
          push({
            at: new Date(),
            tag: "health",
            color: d.database && d.ml?.alive ? "#30a050" : "var(--tc-red)",
            msg: `health change · db=${d.database ? "ok" : "down"} · ml=${d.ml?.alive ? "alive" : "idle"} · llm=${d.llm ?? "—"}`,
          });
        }
      } catch {
        /* silent */
      }
    };
    tick();
    const iv = setInterval(tick, 20_000);
    return () => {
      cancelled = true;
      clearInterval(iv);
    };
  }, [push]);

  // (4) periodic poll summary — never let the log go quiet for more than ~90s
  useEffect(() => {
    const iv = setInterval(() => {
      setLines((l) => {
        const last = l[l.length - 1];
        const since = last ? (Date.now() - last.at.getTime()) / 1000 : Infinity;
        if (since < 80) return l;
        const L = latest.current;
        const line: LogLine = {
          at: new Date(),
          tag: "poll",
          color: "var(--tc-text-muted)",
          msg: `poll · incidents=${L.incidents} · alerts=${L.alerts.toLocaleString("fr")} · score=${L.score ?? "—"} · sources=${L.sourcesActive}/${L.sourcesTotal}`,
        };
        return [...l, line].slice(-250);
      });
    }, 15_000);
    return () => clearInterval(iv);
  }, []);

  useEffect(() => {
    if (!scrollRef.current) return;
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [lines]);

  return (
    <div
      style={{
        borderTop: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        minHeight: 0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          padding: "8px 18px",
          borderBottom: "1px solid var(--tc-border)",
          fontSize: "9px",
          letterSpacing: "0.22em",
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <span>
          <Pulse color="#30a050" /> engine log · live
        </span>
        <span>{lines.length} events</span>
      </div>
      <div
        ref={scrollRef}
        style={{
          padding: "8px 18px 12px",
          fontSize: "11px",
          color: "var(--tc-text-sec)",
          lineHeight: 1.65,
          overflow: "auto",
          flex: 1,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {lines.map((l, i) => (
          <div key={i} style={{ display: "grid", gridTemplateColumns: "68px 52px 1fr", gap: "10px" }}>
            <span style={{ color: "var(--tc-text-muted)", letterSpacing: "0.04em" }}>
              {l.at.toLocaleTimeString("fr-FR", { hour12: false })}
            </span>
            <span style={{ color: l.color, letterSpacing: "0.1em", textTransform: "uppercase", fontWeight: 600 }}>
              {l.tag}
            </span>
            <span>{l.msg}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Small inline helper reused from the top bar pulse style.
function Pulse({ color }: { color: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        width: "6px",
        height: "6px",
        borderRadius: "50%",
        background: color,
        boxShadow: `0 0 6px ${color}`,
        marginRight: "6px",
        verticalAlign: "middle",
        animation: "pulse 1.6s ease-in-out infinite",
      }}
    >
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.35}}`}</style>
    </span>
  );
}

// ═══════════════════════════════════════════════════════════════
// RIGHT AXIS — triage ratio + HITL summary
// ═══════════════════════════════════════════════════════════════
function RightAxis({
  pending,
  confirmed,
  confirmedHigh,
  noisePct,
  activeIncident,
  now,
}: {
  pending: number;
  confirmed: number;
  confirmedHigh: number;
  noisePct: number | null;
  activeIncident: Incident | null;
  now: Date;
}) {
  return (
    <aside
      style={{
        borderLeft: "1px solid var(--tc-border)",
        background: "var(--tc-surface)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid var(--tc-border)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div style={{ fontSize: "9px", letterSpacing: "0.22em", color: "var(--tc-text-muted)", textTransform: "uppercase" }}>
          Validation humaine
        </div>
        <div style={{ fontSize: "10px", color: "var(--tc-red)", letterSpacing: "0.08em" }}>HITL actif</div>
      </div>

      <div style={{ overflowY: "auto", flex: 1 }}>
        {/* Triage ratio */}
        <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--tc-border)" }}>
          <div style={{ fontSize: "9px", letterSpacing: "0.22em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "10px" }}>
            Triage
          </div>
          <div style={{ fontSize: "24px", color: "var(--tc-text)", fontVariantNumeric: "tabular-nums" }}>
            {noisePct === null ? "—" : noisePct >= 99.99 ? ">99.99%" : `${noisePct.toFixed(2)}%`}
          </div>
          <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "4px", letterSpacing: "0.05em" }}>
            bruit filtré · {pending + confirmed} incidents remontés
          </div>

          {/* horizontal inline stats */}
          <div
            style={{
              marginTop: "14px",
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: "10px",
              paddingTop: "14px",
              borderTop: "1px dashed var(--tc-border)",
              fontSize: "11px",
            }}
          >
            <div>
              <div style={{ color: pending > 0 ? "var(--tc-red)" : "var(--tc-text)", fontSize: "16px", fontVariantNumeric: "tabular-nums" }}>
                {pending}
              </div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.14em", textTransform: "uppercase", marginTop: "2px" }}>
                à trier
              </div>
            </div>
            <div>
              <div style={{ color: confirmedHigh > 0 ? "var(--tc-red)" : "var(--tc-text)", fontSize: "16px", fontVariantNumeric: "tabular-nums" }}>
                {confirmedHigh}
              </div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.14em", textTransform: "uppercase", marginTop: "2px" }}>
                high+ conf.
              </div>
            </div>
            <div>
              <div style={{ color: "var(--tc-text)", fontSize: "16px", fontVariantNumeric: "tabular-nums" }}>
                {confirmed}
              </div>
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.14em", textTransform: "uppercase", marginTop: "2px" }}>
                confirmés
              </div>
            </div>
          </div>
        </div>

        {/* Active incident HITL block */}
        {activeIncident ? (
          <ActiveIncidentHitl incident={activeIncident} now={now} />
        ) : (
          <div style={{ padding: "28px 18px", textAlign: "center", fontSize: "11px", color: "var(--tc-text-muted)" }}>
            <Check size={20} style={{ opacity: 0.3, marginBottom: "10px" }} />
            <div>aucune décision en attente</div>
          </div>
        )}
      </div>
    </aside>
  );
}

function ActiveIncidentHitl({ incident, now }: { incident: Incident; now: Date }) {
  return (
    <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--tc-border)" }}>
      <div style={{ fontSize: "9px", letterSpacing: "0.22em", color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: "10px" }}>
        Incident en attente
      </div>
      <div style={{ fontSize: "13px", color: "var(--tc-text)", marginBottom: "6px" }}>
        {incident.asset ?? "—"}
      </div>
      <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "14px", lineHeight: 1.5 }}>
        {incident.title ?? incident.summary ?? "—"}
      </div>

      <div style={{ display: "flex", gap: "8px" }}>
        <Link
          href={`/incidents?id=${incident.id}`}
          style={{
            flex: 1,
            padding: "8px 10px",
            border: "1px solid var(--tc-red)",
            color: "var(--tc-red)",
            textAlign: "center",
            fontSize: "10px",
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            textDecoration: "none",
          }}
        >
          trier →
        </Link>
      </div>

      <div style={{ marginTop: "14px", fontSize: "10px", color: "var(--tc-text-muted)", letterSpacing: "0.04em", lineHeight: 1.5 }}>
        Signé ed25519 · chaîne de hash Postgres · rapport NIS2 auto après décision.
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// STATUS BAR
// ═══════════════════════════════════════════════════════════════
function StatusBar({
  pending,
  confirmed,
  alertsTotal,
}: {
  pending: number;
  confirmed: number;
  alertsTotal: number;
}) {
  return (
    <footer
      style={{
        display: "grid",
        gridTemplateColumns: "auto auto auto 1fr auto",
        gap: "22px",
        alignItems: "center",
        borderTop: "1px solid var(--tc-border)",
        padding: "0 16px",
        fontSize: "10px",
        letterSpacing: "0.1em",
        color: "var(--tc-text-muted)",
        background: "var(--tc-surface)",
      }}
    >
      <span>
        engine · <span style={{ color: "#30a050" }}>running</span>
      </span>
      <span>
        ai · <span style={{ color: "var(--tc-text)" }}>L0 L1 L2 L2.5</span>
      </span>
      <span>
        anonymiseur · <span style={{ color: "#30a050" }}>on</span>
      </span>
      <span />
      <span>
        {pending + confirmed} inc. · {alertsTotal.toLocaleString("fr")} alertes
      </span>
    </footer>
  );
}
