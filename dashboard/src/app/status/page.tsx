"use client";

// System status page — health of the deployment.
// Complementary to the Console at /: the console answers
// "what do I need to do right now?", this page answers
// "is everything wired up and running?".
//
// Keeps the CpuCard the operator likes at the top, with live service
// connection indicators in the SOC design language below.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Database,
  Brain,
  Cpu,
  Radio,
  Shield,
  Network,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  RefreshCcw,
} from "lucide-react";
import { CpuCard } from "@/components/chrome/CpuCard";
import { NeuCard } from "@/components/chrome/NeuCard";
import { t as tr, type Locale } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

type ConnState = "ok" | "down" | "checking";

type HealthResp = {
  status?: string;
  version?: string;
  database?: boolean;
  llm?: string;
  disk_free?: string;
  ml?: {
    alive?: boolean;
    data_days?: number;
    first_data_day?: string | null;
    model_trained?: boolean;
    timestamp?: string;
  };
};

type Situation = {
  global_score?: number;
  computed_at?: string;
  total_open_findings?: number;
  total_active_alerts?: number;
  assets?: Array<{ asset: string; score: number }>;
};

// Backend exposes ML state embedded in /api/tc/health.ml (no separate endpoint).
// `alive=true, model_trained=false, data_days<14` means the engine is running
// and accumulating data — "En apprentissage" in the UI.
type MlHeartbeat = {
  alive?: boolean;
  data_days?: number;
  first_data_day?: string | null;
  model_trained?: boolean;
  timestamp?: string;
};

const MIN_TRAINING_DAYS = 14;

function mlPhase(ml: MlHeartbeat | null, locale: Locale): {
  label: string;
  connected: boolean;
  state: ConnState;
} {
  if (!ml || ml.alive === false) return { label: tr("status_offline", locale), connected: false, state: "down" };
  if (ml.model_trained) return { label: tr("status_operational", locale), connected: true, state: "ok" };
  const d = ml.data_days ?? 0;
  return { label: `${tr("status_learning", locale)} · ${d}/${MIN_TRAINING_DAYS}j`, connected: true, state: "ok" };
}

export default function StatusPage() {
  const locale = useLocale();
  const [health, setHealth] = useState<HealthResp | null>(null);
  const [situation, setSituation] = useState<Situation | null>(null);
  const [dbOk, setDbOk] = useState<ConnState>("checking");
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [ollamaOk, setOllamaOk] = useState<ConnState>("checking");
  const [ml, setMl] = useState<MlHeartbeat | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);
  const [channelCount, setChannelCount] = useState<number | null>(null);
  const [skillCount, setSkillCount] = useState<number | null>(null);
  const [sourcesActive, setSourcesActive] = useState(0);

  const score = situation?.global_score;

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const r = await fetch("/api/tc/health", { signal: AbortSignal.timeout(8000) });
        const d: HealthResp = await r.json();
        if (!mounted) return;
        setHealth(d);
        setDbOk(d.database ? "ok" : "down");
        // Backend embeds ml state here — there is no /api/tc/ml/heartbeat route.
        setMl(d.ml ?? null);
      } catch {
        if (mounted) {
          setHealth(null);
          setDbOk("down");
          setMl(null);
        }
      }

      try {
        const r = await fetch("/api/ollama", { signal: AbortSignal.timeout(8000) });
        const d = await r.json();
        if (!mounted) return;
        const models = (d?.models ?? []).map((m: { name: string }) => m.name);
        setOllamaModels(models);
        setOllamaOk(models.length > 0 ? "ok" : "down");
      } catch {
        if (mounted) setOllamaOk("down");
      }

      try {
        const r = await fetch("/api/tc/intelligence/situation");
        const d = await r.json();
        if (mounted) setSituation(d);
      } catch {
        /* */
      }

      try {
        const r = await fetch("/api/tc/config", { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        if (mounted) {
          const chans = d?.channels ?? {};
          const enabled = Object.values(chans).filter((c: unknown) => (c as { enabled?: boolean })?.enabled).length;
          setChannelCount(enabled);
        }
      } catch {
        /* */
      }

      try {
        const r = await fetch("/api/tc/catalog", { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        if (mounted) {
          const list = Array.isArray(d) ? d : (d?.skills ?? []);
          setSkillCount(Array.isArray(list) ? list.length : null);
        }
      } catch {
        /* */
      }

      try {
        const r = await fetch("/api/tc/sources/status", { signal: AbortSignal.timeout(6000) });
        const d = await r.json();
        if (mounted) {
          const list = (d?.sources ?? []) as Array<{ status: string }>;
          // Match the alive states emitted by /api/tc/sources/status:
          //  - "connected"   = source has logs in the last 24h (the green path)
          //  - "listening"   = always-on inputs (syslog/fluent-bit) waiting for events
          //  - "active"/"ok" = legacy aliases kept for safety
          // The Console panel uses the same set in page.tsx; keep them aligned so
          // the central CpuCard's "Logs" slot does not show red while the
          // engine log clearly streams events from a connected source.
          setSourcesActive(list.filter((s) =>
            ["connected", "listening", "active", "ok"].includes(s.status),
          ).length);
        }
      } catch {
        /* */
      }
    };
    load();
    const iv = setInterval(load, 15_000);
    return () => {
      mounted = false;
      clearInterval(iv);
    };
  }, [refreshTick]);

  const engineOk: ConnState =
    health?.status === "ok" || health?.status === "healthy" ? "ok" : health ? "down" : "checking";

  return (
    <div
      style={{
        padding: "24px 28px 40px",
        fontFamily: "'JetBrains Mono', ui-monospace, monospace",
        fontSize: "12px",
        color: "var(--tc-text)",
        maxWidth: "1600px",
        margin: "0 auto",
      }}
    >
      <PageHeader
        title="System status"
        subtitle={tr("status_subtitle", locale)}
        right={
          <button
            onClick={() => setRefreshTick((t) => t + 1)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              padding: "6px 10px",
              border: "1px solid var(--tc-border)",
              background: "transparent",
              color: "var(--tc-text-sec)",
              fontSize: "10px",
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            <RefreshCcw size={11} />
            Refresh
          </button>
        }
      />

      {/* ─── 3-column: services | CpuCard centered (dominant) | engines ─── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "260px minmax(0,1fr) 260px",
          gap: "20px",
          alignItems: "start",
          marginBottom: "24px",
        }}
      >
        {/* LEFT — Services conteneurs */}
        <div>
          <Section title={tr("status_containerServices", locale)}>
            <ServiceRow icon={Shield} name="threatclaw-core" detail={health?.version ? `v${health.version}` : "—"} state={engineOk} />
            <ServiceRow icon={Database} name="threatclaw-db" detail="postgres 16 · tls=required" state={dbOk} />
            <ServiceRow icon={Cpu} name="ollama" detail={`${ollamaModels.length} ${tr("status_modelsLoaded", locale)}`} state={ollamaOk} />
            <ServiceRow icon={Network} name="threatclaw-dashboard" detail="next 14 · ssr" state={engineOk} />
            {(() => {
              const p = mlPhase(ml, locale);
              return (
                <ServiceRow
                  icon={FileText}
                  name="ml-engine"
                  detail={p.label}
                  state={p.state}
                />
              );
            })()}
            <ServiceRow
              icon={Radio}
              name="fluent-bit"
              detail={`syslog · ${tr("status_fluentBitDisabled", locale)}`}
              state="checking"
              muted
            />
          </Section>
        </div>

        {/* CENTER — CpuCard fills the column */}
        <div style={{ alignSelf: "start", minWidth: 0 }}>
          <NeuCard accent="red" style={{ padding: "14px 16px" }}>
            <CpuCard
              score={score}
              scoreLabel={
                score == null
                  ? tr("status_awaitingFirstCycle", locale)
                  : score >= 80
                    ? tr("status_healthySituation", locale)
                    : score >= 50
                      ? tr("status_attentionPoints", locale)
                      : tr("status_degradedSituation", locale)
              }
              version={health?.version ? `v${health.version}` : ""}
              // 8 slots (4 left + 4 right) matching the original SVG wiring.
              // Order is preserved on purpose — each index maps to a specific
              // cable exit on the chip.
              services={[
                // Left column
                { name: "PostgreSQL",    connected: dbOk === "ok",         color: "#3080d0", detail: "pg16 · pgvector" },
                { name: "Intel. Engine", connected: engineOk === "ok",     color: "#d03020", detail: `${tr("status_correlation", locale)} · Sigma · Graph` },
                { name: "Channels",      connected: (channelCount ?? 0) > 0, color: "#30a050", detail: channelCount != null ? `${channelCount} ${tr("status_activeShort", locale)}` : tr("status_none", locale) },
                { name: "Logs",          connected: sourcesActive > 0,     color: "#f97316", detail: `${sourcesActive} ${tr("status_activeSources", locale)}` },
                // Right column
                { name: "AI",            connected: ollamaOk === "ok",     color: "#9060d0", detail: `${ollamaModels.length} ${tr("status_modelShort", locale)}`, restartable: true },
                { name: "ML Engine",     connected: mlPhase(ml, locale).connected, color: "#d09020", detail: mlPhase(ml, locale).label, restartable: true },
                { name: "Skills",        connected: (skillCount ?? 0) > 0, color: "#06b6d4", detail: skillCount != null ? `${skillCount} skills` : "—" },
                { name: "Dashboard",     connected: true,                  color: "#b0a8a0", detail: "Next.js 16 · SSR" },
              ]}
            />
          </NeuCard>
        </div>

        {/* RIGHT — Moteurs internes */}
        <div>
          <Section title={tr("status_internalEngines", locale)}>
            <EngineRow name="Intelligence Engine" detail={`${tr("status_cycle5min", locale)} · scoring`} ok={engineOk === "ok"} locale={locale} />
            <EngineRow name="Sigma Engine" detail={`84 ${tr("status_rules", locale)} · pack V49`} ok={engineOk === "ok"} locale={locale} />
            <EngineRow name="Bloom Filter" detail="IoC live · 18k entries" ok={engineOk === "ok"} locale={locale} />
            <EngineRow name="Graph Intelligence" detail="STIX 2.1 · Apache AGE" ok={engineOk === "ok"} locale={locale} />
            <EngineRow
              name="ML Anomaly Detection"
              detail={ml?.model_trained ? "Isolation Forest" : ml?.alive ? `${tr("status_learning", locale)} · ${ml.data_days ?? 0}/${MIN_TRAINING_DAYS}j` : tr("status_inactive", locale)}
              ok={(ml?.alive ?? false) && (ml?.model_trained ?? false)}
              locale={locale}
            />
            <EngineRow
              name="ML DNS Classifier"
              detail={ml?.alive ? "Random Forest · DGA" : tr("status_inactive", locale)}
              ok={ml?.alive ?? false}
              locale={locale}
            />
          </Section>
        </div>
      </div>

      <Section title={tr("status_localAiModels", locale)}>
        {ollamaModels.length === 0 ? (
          <EmptyLine text={ollamaOk === "down" ? tr("status_ollamaUnreachable", locale) : tr("status_noModelLoaded", locale)} />
        ) : (
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
              gap: "8px",
            }}
          >
            {ollamaModels.map((m) => (
              <div
                key={m}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "8px 10px",
                  border: "1px solid var(--tc-border)",
                  fontSize: "11px",
                  color: "var(--tc-text)",
                }}
              >
                <Brain size={12} color="var(--tc-text-sec)" />
                <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{m}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title={tr("status_volumetryLastCycle", locale)}>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "10px",
          }}
        >
          <StatLine label={tr("status_activeAlerts", locale)} value={situation?.total_active_alerts ?? "—"} />
          <StatLine label={tr("status_openFindings", locale)} value={situation?.total_open_findings ?? "—"} />
          <StatLine label={tr("status_trackedAssets", locale)} value={situation?.assets?.length ?? "—"} />
          <StatLine
            label={tr("status_lastCycle", locale)}
            value={situation?.computed_at ? formatRelativeShort(situation.computed_at) : "—"}
          />
        </div>
      </Section>

      <div style={{ textAlign: "center", marginTop: "24px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
        <Link href="/" style={{ color: "var(--tc-text-sec)", textDecoration: "none" }}>
          ← {tr("status_backToConsole", locale)}
        </Link>
      </div>
    </div>
  );
}

function formatRelativeShort(iso: string) {
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s`;
  if (diff < 3600) return `${Math.round(diff / 60)}m`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h`;
  return `${Math.round(diff / 86400)}j`;
}

function PageHeader({ title, subtitle, right }: { title: string; subtitle: string; right?: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "24px", display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
      <div>
        <div style={{ fontSize: "9px", letterSpacing: "0.22em", color: "var(--tc-text-muted)", textTransform: "uppercase" }}>
          {title}
        </div>
        <div style={{ fontSize: "13px", color: "var(--tc-text-sec)", marginTop: "6px", maxWidth: "700px", lineHeight: 1.5 }}>
          {subtitle}
        </div>
      </div>
      {right}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: "18px" }}>
      <div
        style={{
          fontSize: "9px",
          letterSpacing: "0.22em",
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          marginBottom: "10px",
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

function ServiceRow({
  icon: Icon,
  name,
  detail,
  state,
  muted,
}: {
  icon: React.ElementType;
  name: string;
  detail: string;
  state: ConnState;
  muted?: boolean;
}) {
  const color =
    state === "ok" ? "#30a050" : state === "down" ? "var(--tc-red)" : "var(--tc-text-muted)";
  const Status = state === "ok" ? CheckCircle2 : state === "down" ? AlertTriangle : Loader2;
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "20px 1fr auto",
        gap: "10px",
        alignItems: "center",
        padding: "10px 0",
        borderBottom: "1px dashed var(--tc-border)",
        opacity: muted ? 0.55 : 1,
      }}
    >
      <Icon size={13} color="var(--tc-text-sec)" />
      <div>
        <div style={{ fontSize: "12px", color: "var(--tc-text)" }}>{name}</div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{detail}</div>
      </div>
      <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "10px", color, letterSpacing: "0.12em", textTransform: "uppercase" }}>
        <Status size={11} className={state === "checking" ? "animate-spin" : undefined} />
        {state}
      </span>
    </div>
  );
}

function EngineRow({ name, detail, ok, locale }: { name: string; detail: string; ok: boolean; locale: Locale }) {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "8px 1fr auto",
        gap: "12px",
        alignItems: "center",
        padding: "10px 0",
        borderBottom: "1px dashed var(--tc-border)",
      }}
    >
      <span
        style={{
          width: "6px",
          height: "6px",
          borderRadius: "50%",
          background: ok ? "#30a050" : "var(--tc-text-muted)",
          boxShadow: ok ? "0 0 6px #30a050" : "none",
        }}
      />
      <div>
        <div style={{ fontSize: "12px", color: "var(--tc-text)" }}>{name}</div>
        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "2px" }}>{detail}</div>
      </div>
      <span style={{ fontSize: "10px", color: ok ? "#30a050" : "var(--tc-text-muted)", letterSpacing: "0.12em", textTransform: "uppercase" }}>
        {ok ? tr("status_active", locale) : tr("status_inactive", locale)}
      </span>
    </div>
  );
}

function StatLine({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{ border: "1px solid var(--tc-border)", padding: "10px 12px" }}>
      <div style={{ fontSize: "18px", color: "var(--tc-text)", fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", letterSpacing: "0.14em", textTransform: "uppercase", marginTop: "2px" }}>
        {label}
      </div>
    </div>
  );
}

function EmptyLine({ text }: { text: string }) {
  return <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", fontStyle: "italic", padding: "10px 0" }}>{text}</div>;
}
