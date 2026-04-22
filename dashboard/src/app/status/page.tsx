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

type ConnState = "ok" | "down" | "checking";

type HealthResp = {
  status?: string;
  version?: string;
  database?: boolean;
  llm?: string;
};

type Situation = {
  global_score?: number;
  computed_at?: string;
  total_open_findings?: number;
  total_active_alerts?: number;
  assets?: Array<{ asset: string; score: number }>;
};

type MlHeartbeat = {
  last_run?: string;
  model_trained?: boolean;
  data_days?: number;
  dns_active?: boolean;
  anomaly_active?: boolean;
};

export default function StatusPage() {
  const [health, setHealth] = useState<HealthResp | null>(null);
  const [situation, setSituation] = useState<Situation | null>(null);
  const [dbOk, setDbOk] = useState<ConnState>("checking");
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [ollamaOk, setOllamaOk] = useState<ConnState>("checking");
  const [ml, setMl] = useState<MlHeartbeat | null>(null);
  const [refreshTick, setRefreshTick] = useState(0);

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
      } catch {
        if (mounted) {
          setHealth(null);
          setDbOk("down");
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
        const r = await fetch("/api/tc/ml/heartbeat");
        const d = await r.json();
        if (mounted) setMl(d);
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
        subtitle="Santé du déploiement — services, connecteurs, moteurs internes. Complémentaire de la console."
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

      {/* ─── 3-column: services | CpuCard centered | engines ─── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr auto 1fr",
          gap: "24px",
          alignItems: "start",
          marginBottom: "24px",
        }}
      >
        {/* LEFT — Services conteneurs */}
        <div>
          <Section title="Services conteneurs">
            <ServiceRow icon={Shield} name="threatclaw-core" detail={health?.version ? `v${health.version}` : "—"} state={engineOk} />
            <ServiceRow icon={Database} name="threatclaw-db" detail="postgres 16 · tls=required" state={dbOk} />
            <ServiceRow icon={Cpu} name="ollama" detail={`${ollamaModels.length} modèles chargés`} state={ollamaOk} />
            <ServiceRow icon={Network} name="threatclaw-dashboard" detail="next 14 · ssr" state={engineOk} />
            <ServiceRow
              icon={FileText}
              name="ml-engine"
              detail={ml ? `last run ${formatLastRun(ml.last_run)}` : "idle"}
              state={ml?.last_run ? "ok" : "checking"}
            />
            <ServiceRow
              icon={Radio}
              name="fluent-bit"
              detail="syslog · désactivé (Wazuh tient 514)"
              state="checking"
              muted
            />
          </Section>
        </div>

        {/* CENTER — compact CpuCard */}
        <div style={{ width: "380px", alignSelf: "start" }}>
          <NeuCard accent="red" style={{ padding: "10px 12px" }}>
            <CpuCard
              score={score}
              scoreLabel={
                score == null
                  ? "En attente du premier cycle"
                  : score >= 80
                    ? "Situation saine"
                    : score >= 50
                      ? "Points d'attention"
                      : "Situation dégradée"
              }
              version={health?.version ? `v${health.version}` : ""}
              services={[
                { name: "PostgreSQL", connected: dbOk === "ok", color: "#3080d0", detail: "pg16 · pgvector" },
                { name: "AI", connected: ollamaOk === "ok", color: "#9060d0", detail: `${ollamaModels.length} modèle(s)`, restartable: true },
                { name: "Intel.", connected: engineOk === "ok", color: "#d03020", detail: "Corrélation" },
                { name: "Sigma", connected: engineOk === "ok", color: "#d09020", detail: "Règles" },
                { name: "Graph", connected: engineOk === "ok", color: "#30a050", detail: "STIX 2.1" },
                { name: "ML", connected: ml?.model_trained ?? false, color: "#06b6d4", detail: ml?.model_trained ? "Trained" : "Learning", restartable: true },
              ]}
            />
          </NeuCard>
        </div>

        {/* RIGHT — Moteurs internes */}
        <div>
          <Section title="Moteurs internes">
            <EngineRow name="Intelligence Engine" detail="cycle 5 min · scoring" ok={engineOk === "ok"} />
            <EngineRow name="Sigma Engine" detail="84 règles · pack V49" ok={engineOk === "ok"} />
            <EngineRow name="Bloom Filter" detail="IoC live · 18k entries" ok={engineOk === "ok"} />
            <EngineRow name="Graph Intelligence" detail="STIX 2.1 · Apache AGE" ok={engineOk === "ok"} />
            <EngineRow
              name="ML Anomaly Detection"
              detail={ml?.model_trained ? "Isolation Forest" : ml ? `apprentissage (${ml.data_days ?? 0}/14j)` : "inactif"}
              ok={ml?.anomaly_active ?? false}
            />
            <EngineRow
              name="ML DNS Classifier"
              detail={ml?.dns_active ? "Random Forest · DGA" : "inactif"}
              ok={ml?.dns_active ?? false}
            />
          </Section>
        </div>
      </div>

      <Section title="Modèles IA locaux (Ollama)">
        {ollamaModels.length === 0 ? (
          <EmptyLine text={ollamaOk === "down" ? "ollama injoignable" : "aucun modèle chargé"} />
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

      <Section title="Volumétrie · dernier cycle">
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: "10px",
          }}
        >
          <StatLine label="Alertes actives" value={situation?.total_active_alerts ?? "—"} />
          <StatLine label="Findings ouverts" value={situation?.total_open_findings ?? "—"} />
          <StatLine label="Assets suivis" value={situation?.assets?.length ?? "—"} />
          <StatLine
            label="Dernier cycle"
            value={situation?.computed_at ? formatRelativeShort(situation.computed_at) : "—"}
          />
        </div>
      </Section>

      <div style={{ textAlign: "center", marginTop: "24px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
        <Link href="/" style={{ color: "var(--tc-text-sec)", textDecoration: "none" }}>
          ← retour à la console
        </Link>
      </div>
    </div>
  );
}

function formatLastRun(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return `il y a ${Math.round(diff)}s`;
  if (diff < 3600) return `il y a ${Math.round(diff / 60)}m`;
  if (diff < 86400) return `il y a ${Math.round(diff / 3600)}h`;
  return d.toLocaleDateString("fr-FR");
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

function EngineRow({ name, detail, ok }: { name: string; detail: string; ok: boolean }) {
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
        {ok ? "actif" : "inactif"}
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
