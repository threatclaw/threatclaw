"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { PageShell } from "@/components/chrome/PageShell";
import { ErrorBanner } from "@/components/chrome/ErrorBanner";
import { ArrowLeft, Download, RefreshCw, ExternalLink } from "lucide-react";

type TechniqueCoverage = {
  techniqueID: string;
  rule_count: number;
  fire_count_30d: number;
  weight: number;
  rules: string[];
};

type CoverageResponse = {
  coverage: TechniqueCoverage[];
  total_techniques: number;
  total_rules_enabled: number;
  layer: unknown;
};

// 14 ATT&CK Enterprise tactics in canonical order. Used as columns.
const TACTICS: { id: string; nameFr: string; nameEn: string }[] = [
  { id: "TA0043", nameFr: "Reconnaissance", nameEn: "Reconnaissance" },
  { id: "TA0042", nameFr: "Dev. ressources", nameEn: "Resource Dev." },
  { id: "TA0001", nameFr: "Accès initial", nameEn: "Initial Access" },
  { id: "TA0002", nameFr: "Exécution", nameEn: "Execution" },
  { id: "TA0003", nameFr: "Persistance", nameEn: "Persistence" },
  { id: "TA0004", nameFr: "Élévation priv.", nameEn: "Priv. Escalation" },
  { id: "TA0005", nameFr: "Évasion", nameEn: "Defense Evasion" },
  { id: "TA0006", nameFr: "Accès crédentiels", nameEn: "Credential Access" },
  { id: "TA0007", nameFr: "Découverte", nameEn: "Discovery" },
  { id: "TA0008", nameFr: "Mouv. latéral", nameEn: "Lateral Movement" },
  { id: "TA0009", nameFr: "Collecte", nameEn: "Collection" },
  { id: "TA0011", nameFr: "C&C", nameEn: "Command & Control" },
  { id: "TA0010", nameFr: "Exfiltration", nameEn: "Exfiltration" },
  { id: "TA0040", nameFr: "Impact", nameEn: "Impact" },
];

// Static mapping of common techniques → tactic. ATT&CK has 200+ but we
// cover the ones likely to appear in our rules. Anything not mapped here
// lands in an "Other" column at the end.
const TECHNIQUE_TACTIC: Record<string, string> = {
  // Initial Access
  "T1190": "TA0001", "T1078": "TA0001", "T1133": "TA0001", "T1566": "TA0001",
  // Execution
  "T1059": "TA0002", "T1059.001": "TA0002", "T1059.003": "TA0002", "T1059.004": "TA0002",
  "T1053": "TA0002", "T1053.003": "TA0002", "T1053.005": "TA0002", "T1569": "TA0002",
  // Persistence
  "T1543": "TA0003", "T1543.003": "TA0003", "T1547": "TA0003", "T1547.001": "TA0003",
  "T1546": "TA0003", "T1546.003": "TA0003", "T1098": "TA0003", "T1136": "TA0003",
  "T1136.001": "TA0003", "T1136.003": "TA0003",
  // Privilege Escalation
  "T1548": "TA0004", "T1548.003": "TA0004",
  // Defense Evasion
  "T1027": "TA0005", "T1140": "TA0005", "T1197": "TA0005", "T1562": "TA0005",
  "T1562.001": "TA0005", "T1562.004": "TA0005", "T1564": "TA0005", "T1564.003": "TA0005",
  "T1620": "TA0005", "T1070": "TA0005", "T1070.001": "TA0005", "T1070.002": "TA0005",
  // Credential Access
  "T1110": "TA0006", "T1110.001": "TA0006", "T1003": "TA0006", "T1003.001": "TA0006",
  "T1003.006": "TA0006", "T1558": "TA0006", "T1558.001": "TA0006", "T1558.003": "TA0006",
  "T1557": "TA0006", "T1557.002": "TA0006", "T1552": "TA0006", "T1056": "TA0006",
  // Discovery
  "T1046": "TA0007", "T1595": "TA0007",
  // Lateral Movement
  "T1021": "TA0008", "T1021.001": "TA0008", "T1021.002": "TA0008", "T1021.006": "TA0008",
  "T1550": "TA0008", "T1550.002": "TA0008",
  // Collection
  "T1530": "TA0009", "T1105": "TA0009",
  // Command & Control
  "T1071": "TA0011", "T1071.004": "TA0011", "T1571": "TA0011",
  // Exfiltration
  "T1567": "TA0010", "T1567.002": "TA0010",
  // Impact
  "T1485": "TA0040", "T1496": "TA0040", "T1498": "TA0040", "T1498.002": "TA0040",
  "T1499": "TA0040", "T1499.004": "TA0040",
  // Resource Development
  "T1078.003": "TA0042",
};

function tacticFor(techniqueId: string): string {
  if (TECHNIQUE_TACTIC[techniqueId]) return TECHNIQUE_TACTIC[techniqueId];
  // Fall back to the parent technique (drop the sub-id) before declaring "other".
  const parent = techniqueId.split(".")[0];
  return TECHNIQUE_TACTIC[parent] || "OTHER";
}

function coverageColor(weight: number, max: number): string {
  if (max === 0 || weight === 0) return "var(--tc-input)";
  const ratio = Math.min(1, weight / max);
  // Lerp from soft red to deep brand red.
  if (ratio < 0.33) return "rgba(208,80,48,0.20)";
  if (ratio < 0.66) return "rgba(208,80,48,0.45)";
  return "rgba(122,16,16,0.75)";
}

export default function SigmaCoveragePage() {
  const router = useRouter();
  const locale = useLocale();
  const labels = useMemo(() => ({
    title:     locale === "fr" ? "Couverture MITRE ATT&CK" : "MITRE ATT&CK coverage",
    subtitle:  locale === "fr"
      ? "Techniques couvertes par les règles actives. Chaque cellule = une technique. Plus c'est foncé, plus on a de règles dessus."
      : "Techniques covered by enabled detection rules. Each cell is a technique. Darker = more rules.",
    back:      locale === "fr" ? "Règles" : "Rules",
    refresh:   locale === "fr" ? "Actualiser" : "Refresh",
    loading:   locale === "fr" ? "Chargement..." : "Loading...",
    download:  locale === "fr" ? "Layer Navigator (JSON)" : "Download Navigator layer",
    openNav:   locale === "fr" ? "Ouvrir dans Navigator" : "Open in Navigator",
    coveredT:  locale === "fr" ? "Techniques couvertes" : "Techniques covered",
    activeR:   locale === "fr" ? "Règles actives" : "Active rules",
    rulesOn:   locale === "fr" ? "Règles" : "Rules",
    fires30:   locale === "fr" ? "Matches 30j" : "Matches 30d",
    other:     locale === "fr" ? "Autres / Non mappé" : "Other / Unmapped",
    legendLow: locale === "fr" ? "Faible" : "Low",
    legendHigh:locale === "fr" ? "Forte" : "High",
    legendNone:locale === "fr" ? "Aucune" : "None",
  }), [locale]);

  const [data, setData] = useState<CoverageResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hovered, setHovered] = useState<TechniqueCoverage | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const res = await fetch("/api/tc/sigma/coverage/mitre");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: CoverageResponse = await res.json();
      setData(json);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Group by tactic.
  const byTactic = useMemo(() => {
    const map: Record<string, TechniqueCoverage[]> = {};
    if (!data) return map;
    for (const t of data.coverage) {
      const tac = tacticFor(t.techniqueID);
      if (!map[tac]) map[tac] = [];
      map[tac].push(t);
    }
    for (const k of Object.keys(map)) {
      map[k].sort((a, b) => b.weight - a.weight);
    }
    return map;
  }, [data]);

  const maxWeight = useMemo(() => {
    if (!data) return 1;
    return Math.max(1, ...data.coverage.map(c => c.weight));
  }, [data]);

  const handleDownload = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data.layer, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "threatclaw-mitre-layer.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <PageShell title={labels.title}>
        <NeuCard><div style={{ textAlign: "center", padding: "32px", color: "var(--tc-text-muted)" }}>{labels.loading}</div></NeuCard>
      </PageShell>
    );
  }

  if (error || !data) {
    return (
      <PageShell title={labels.title}>
        <ErrorBanner message={error || "—"} onRetry={load} />
      </PageShell>
    );
  }

  const otherTechniques = byTactic["OTHER"] || [];
  const columns = TACTICS.filter(t => byTactic[t.id] && byTactic[t.id].length > 0);

  return (
    <PageShell
      title={labels.title}
      subtitle={labels.subtitle}
      right={
        <div style={{ display: "flex", gap: "6px" }}>
          <ChromeButton onClick={() => router.push("/sigma")} variant="glass">
            <ArrowLeft size={13} /> {labels.back}
          </ChromeButton>
          <ChromeButton onClick={handleDownload} variant="glass">
            <Download size={13} /> {labels.download}
          </ChromeButton>
          <ChromeButton onClick={load} variant="glass">
            <RefreshCw size={13} />
          </ChromeButton>
        </div>
      }
    >
      {/* Counter strip */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "16px", flexWrap: "wrap" }}>
        <Pill label={labels.coveredT} value={data.total_techniques} />
        <Pill label={labels.activeR} value={data.total_rules_enabled} />
      </div>

      {/* Matrix */}
      <NeuCard style={{ padding: "16px", overflow: "auto" }}>
        <div style={{ display: "grid",
          gridTemplateColumns: `repeat(${columns.length}, minmax(140px, 1fr))`,
          gap: "8px", minWidth: `${columns.length * 150}px` }}>
          {columns.map(tactic => (
            <div key={tactic.id} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              <div style={{ fontSize: "10px", letterSpacing: "0.08em", textTransform: "uppercase",
                color: "var(--tc-text-muted)", fontWeight: 700,
                paddingBottom: "6px", borderBottom: "1px solid var(--tc-border)",
                marginBottom: "4px" }}>
                {locale === "fr" ? tactic.nameFr : tactic.nameEn}
                <span style={{ fontSize: "9px", marginLeft: "6px", color: "var(--tc-text-muted)", fontWeight: 400 }}>
                  ({byTactic[tactic.id].length})
                </span>
              </div>
              {byTactic[tactic.id].map(t => (
                <div key={t.techniqueID}
                  onMouseEnter={() => setHovered(t)}
                  onMouseLeave={() => setHovered(prev => prev === t ? null : prev)}
                  onClick={() => {
                    if (t.rules.length === 1) router.push(`/sigma/${encodeURIComponent(t.rules[0])}`);
                  }}
                  style={{
                    padding: "8px 10px",
                    background: coverageColor(t.weight, maxWeight),
                    border: "1px solid var(--tc-border)",
                    borderRadius: "var(--tc-radius-sm)",
                    cursor: t.rules.length > 0 ? "pointer" : "default",
                    fontSize: "11px",
                    color: t.weight > maxWeight * 0.5 ? "white" : "var(--tc-text)",
                  }}>
                  <div style={{ fontFamily: "monospace", fontWeight: 700 }}>{t.techniqueID}</div>
                  <div style={{ fontSize: "10px", opacity: 0.85, marginTop: "2px" }}>
                    {t.rule_count} {labels.rulesOn} · {t.fire_count_30d} {labels.fires30}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>

        {otherTechniques.length > 0 && (
          <div style={{ marginTop: "20px", paddingTop: "16px", borderTop: "1px solid var(--tc-border)" }}>
            <div style={{ fontSize: "10px", letterSpacing: "0.08em", textTransform: "uppercase",
              color: "var(--tc-text-muted)", fontWeight: 700, marginBottom: "8px" }}>
              {labels.other} ({otherTechniques.length})
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
              {otherTechniques.map(t => (
                <div key={t.techniqueID}
                  onClick={() => { if (t.rules.length === 1) router.push(`/sigma/${encodeURIComponent(t.rules[0])}`); }}
                  style={{ padding: "6px 10px", background: coverageColor(t.weight, maxWeight),
                    border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
                    fontSize: "11px", fontFamily: "monospace", cursor: t.rules.length > 0 ? "pointer" : "default",
                    color: t.weight > maxWeight * 0.5 ? "white" : "var(--tc-text)" }}>
                  {t.techniqueID}
                </div>
              ))}
            </div>
          </div>
        )}
      </NeuCard>

      {/* Legend */}
      <div style={{ marginTop: "12px", display: "flex", gap: "16px", alignItems: "center",
        fontSize: "11px", color: "var(--tc-text-muted)" }}>
        <span>{labels.legendNone}</span>
        <div style={{ width: "20px", height: "12px", background: "var(--tc-input)", border: "1px solid var(--tc-border)" }} />
        <span>{labels.legendLow}</span>
        <div style={{ width: "20px", height: "12px", background: "rgba(208,80,48,0.20)", border: "1px solid var(--tc-border)" }} />
        <div style={{ width: "20px", height: "12px", background: "rgba(208,80,48,0.45)", border: "1px solid var(--tc-border)" }} />
        <div style={{ width: "20px", height: "12px", background: "rgba(122,16,16,0.75)", border: "1px solid var(--tc-border)" }} />
        <span>{labels.legendHigh}</span>
      </div>

      {/* Hover detail */}
      {hovered && (
        <div style={{ position: "fixed", bottom: "16px", right: "16px", maxWidth: "320px", zIndex: 50 }}>
          <NeuCard style={{ padding: "12px 14px" }}>
            <div style={{ fontFamily: "monospace", fontWeight: 700, fontSize: "12px", marginBottom: "4px" }}>
              {hovered.techniqueID}
            </div>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "8px" }}>
              {hovered.rule_count} {labels.rulesOn} · {hovered.fire_count_30d} {labels.fires30}
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
              {hovered.rules.slice(0, 5).map(rid => (
                <span key={rid} style={{ fontSize: "10px", fontFamily: "monospace", color: "var(--tc-blue)" }}>
                  · {rid}
                </span>
              ))}
              {hovered.rules.length > 5 && (
                <span style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>
                  +{hovered.rules.length - 5}
                </span>
              )}
            </div>
          </NeuCard>
        </div>
      )}
    </PageShell>
  );
}

function Pill({ label, value }: { label: string; value: number }) {
  return (
    <div style={{
      padding: "8px 14px", borderRadius: "var(--tc-radius-md)",
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-input)",
      display: "flex", alignItems: "center", gap: "10px",
    }}>
      <span style={{ fontWeight: 800, fontSize: "20px", color: "var(--tc-text)", fontFamily: "monospace" }}>{value}</span>
      <span style={{ color: "var(--tc-text-muted)", textTransform: "uppercase",
        fontSize: "10px", letterSpacing: "0.10em" }}>{label}</span>
    </div>
  );
}
