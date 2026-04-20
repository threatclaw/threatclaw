"use client";

import React, { useState, useEffect, useMemo } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import {
  FileText, Shield, Download, Clock, Globe, Database,
  AlertTriangle, Server, Loader2, CheckCircle2, Lock,
  BarChart3, Users, Eye, Star, Siren, Gavel, Radio, Archive, X,
} from "lucide-react";

// ─────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────

type Temporality = "snapshot-now" | "incident-bound" | "period-bound" | "all-time";
type ExportCategory = "incident-response" | "compliance-audit" | "threat-intel" | "operations";

interface LegalRequirement {
  region: "eu" | "us" | "intl";
  standard: string;         // "NIS2 Art.23", "GDPR Art.33", ...
  deadlineHours?: number;   // 24, 72, 720 (30j)
  mandatory: boolean;
}

interface ExportItem {
  id: string;
  titleKey: string;
  titleFallback: string;
  descKey: string;
  descFallback: string;
  icon: React.ElementType;
  formats: string[];
  color: string;
  category: ExportCategory;
  endpoint: string;
  regions: ("eu" | "us" | "intl")[];
  temporality: Temporality;
  frequency?: "monthly" | "annual" | "quarterly" | "on-demand" | "real-time";
  legal?: LegalRequirement;
  requiresIncident?: boolean;
  supportsGdprOverride?: boolean;
  notImplemented?: boolean;   // e.g. audit-trail v1 stubbed
}

// ─────────────────────────────────────────────────────────
// Exports catalogue — regrouped by usage pattern
// ─────────────────────────────────────────────────────────

const EXPORTS: ExportItem[] = [
  // ── INCIDENT & BREACH RESPONSE ───────────────────────────
  { id: "nis2-early", titleKey: "export_nis2_early", titleFallback: "NIS2 — Early Warning (24h)",
    descKey: "export_nis2_early_desc", descFallback: "Initial mandatory notification. Incident nature, affected systems, immediate measures.",
    icon: Siren, formats: ["PDF", "JSON"], color: "#e04040", category: "incident-response",
    endpoint: "/api/tc/exports/nis2-early-warning", regions: ["eu"],
    temporality: "incident-bound", requiresIncident: true,
    legal: { region: "eu", standard: "NIS2 Art.23", deadlineHours: 24, mandatory: true } },

  { id: "nis2-intermediate", titleKey: "export_nis2_inter", titleFallback: "NIS2 — Intermediate (72h)",
    descKey: "export_nis2_inter_desc", descFallback: "Preliminary cause analysis, identified IOCs, corrective actions in progress.",
    icon: FileText, formats: ["PDF", "JSON"], color: "#e04040", category: "incident-response",
    endpoint: "/api/tc/exports/nis2-intermediate", regions: ["eu"],
    temporality: "incident-bound", requiresIncident: true,
    legal: { region: "eu", standard: "NIS2 Art.23", deadlineHours: 72, mandatory: true } },

  { id: "nis2-final", titleKey: "export_nis2_final", titleFallback: "NIS2 — Final Report (1 month)",
    descKey: "export_nis2_final_desc", descFallback: "Complete post-incident analysis, root cause, timeline, recommendations.",
    icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", category: "incident-response",
    endpoint: "/api/tc/exports/nis2-final", regions: ["eu"],
    temporality: "incident-bound", requiresIncident: true,
    legal: { region: "eu", standard: "NIS2 Art.23", deadlineHours: 720, mandatory: true } },

  { id: "gdpr-art33", titleKey: "export_gdpr", titleFallback: "GDPR — Data Breach (Art. 33)",
    descKey: "export_gdpr_desc", descFallback: "Personal data breach notification to CNIL. Auto-detect PII involvement, RSSI override available.",
    icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", category: "incident-response",
    endpoint: "/api/tc/exports/gdpr-article33", regions: ["eu"],
    temporality: "incident-bound", requiresIncident: false, supportsGdprOverride: true,
    legal: { region: "eu", standard: "GDPR Art.33", deadlineHours: 72, mandatory: true } },

  { id: "nist-incident", titleKey: "export_nist", titleFallback: "NIST SP 800-61 — Incident Report",
    descKey: "export_nist_desc", descFallback: "NIST CSF 2.0 format. Compatible with US federal agencies and international standards.",
    icon: Globe, formats: ["PDF", "JSON"], color: "#d06020", category: "incident-response",
    endpoint: "/api/tc/exports/nist-incident", regions: ["us", "intl"],
    temporality: "incident-bound", requiresIncident: false,
    legal: { region: "us", standard: "NIST CSF 2.0", mandatory: false } },

  { id: "iso27001", titleKey: "export_iso27001", titleFallback: "ISO 27001 — Incident Report",
    descKey: "export_iso27001_desc", descFallback: "Controls A.5.24-A.5.28. Classification, response, evidence, lessons learned.",
    icon: Lock, formats: ["PDF", "JSON"], color: "#d06020", category: "incident-response",
    endpoint: "/api/tc/exports/iso27001-incident", regions: ["eu", "us", "intl"],
    temporality: "incident-bound", requiresIncident: false,
    legal: { region: "intl", standard: "ISO/IEC 27001:2022", mandatory: false } },

  // ── COMPLIANCE & AUDIT ───────────────────────────────────
  { id: "executive", titleKey: "export_executive", titleFallback: "Executive Report",
    descKey: "export_executive_desc", descFallback: "Security score, monthly incidents, business risks. Non-technical language for management.",
    icon: BarChart3, formats: ["PDF"], color: "#3080d0", category: "compliance-audit",
    endpoint: "/api/tc/exports/executive-report", regions: ["eu", "us", "intl"],
    temporality: "period-bound", frequency: "monthly" },

  { id: "technical", titleKey: "export_technical", titleFallback: "Technical Report",
    descKey: "export_technical_desc", descFallback: "All findings, CVEs, MITRE ATT&CK TTPs, detailed recommendations.",
    icon: FileText, formats: ["PDF"], color: "#3080d0", category: "compliance-audit",
    endpoint: "/api/tc/exports/technical-report", regions: ["eu", "us", "intl"],
    temporality: "period-bound", frequency: "monthly" },

  { id: "nis2-art21", titleKey: "export_nis2_art21", titleFallback: "NIS2 Article 21 — Compliance Checklist",
    descKey: "export_nis2_art21_desc", descFallback: "10 mandatory security measures with score and evidence per measure. Annual audit or post-incident.",
    icon: Gavel, formats: ["PDF", "JSON"], color: "#3080d0", category: "compliance-audit",
    endpoint: "/api/tc/exports/nis2-article21", regions: ["eu"],
    temporality: "snapshot-now", frequency: "annual",
    legal: { region: "eu", standard: "NIS2 Art.21", mandatory: true } },

  { id: "audit-trail", titleKey: "export_audit", titleFallback: "Audit Trail (Immutable Log)",
    descKey: "export_audit_desc", descFallback: "All ThreatClaw actions with hash-chained integrity. Legal forensic evidence over a chosen period.",
    icon: Archive, formats: ["PDF", "JSON"], color: "#3080d0", category: "compliance-audit",
    endpoint: "/api/tc/exports/audit-trail", regions: ["eu", "us", "intl"],
    temporality: "period-bound", frequency: "on-demand" },

  // ── THREAT INTELLIGENCE & CTI ────────────────────────────
  { id: "stix2", titleKey: "export_stix", titleFallback: "STIX 2.1 Bundle",
    descKey: "export_stix_desc", descFallback: "Full attack graph. Compatible with OpenCTI, MISP, Splunk, QRadar.",
    icon: Globe, formats: ["JSON"], color: "#9060d0", category: "threat-intel",
    endpoint: "/api/tc/exports/stix2", regions: ["eu", "us", "intl"],
    temporality: "snapshot-now", frequency: "real-time" },

  { id: "misp", titleKey: "export_misp", titleFallback: "MISP Event",
    descKey: "export_misp_desc", descFallback: "Threat intel sharing standard. Compatible with national CERTs.",
    icon: Users, formats: ["JSON"], color: "#9060d0", category: "threat-intel",
    endpoint: "/api/tc/exports/misp-event", regions: ["eu", "us", "intl"],
    temporality: "snapshot-now", frequency: "real-time" },

  { id: "iocs", titleKey: "export_iocs", titleFallback: "IOCs (Indicators of Compromise)",
    descKey: "export_iocs_desc", descFallback: "Malicious IPs, hashes, suspicious domains. Importable into firewall/EDR.",
    icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#9060d0", category: "threat-intel",
    endpoint: "/api/tc/exports/iocs", regions: ["eu", "us", "intl"],
    temporality: "snapshot-now", frequency: "real-time" },

  // ── OPERATIONS & INVENTORY ───────────────────────────────
  { id: "assets-csv", titleKey: "export_assets", titleFallback: "Assets Inventory",
    descKey: "export_assets_desc", descFallback: "Complete asset list with category, criticality, IP, OS.",
    icon: Server, formats: ["CSV", "JSON"], color: "#30a050", category: "operations",
    endpoint: "/api/tc/exports/assets", regions: ["eu", "us", "intl"],
    temporality: "all-time" },

  { id: "alerts-csv", titleKey: "export_alerts", titleFallback: "Security Alerts",
    descKey: "export_alerts_desc", descFallback: "All Sigma alerts with level, source, timestamps.",
    icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#30a050", category: "operations",
    endpoint: "/api/tc/exports/alerts", regions: ["eu", "us", "intl"],
    temporality: "all-time" },

  { id: "findings-csv", titleKey: "export_findings", titleFallback: "Vulnerabilities (Findings)",
    descKey: "export_findings_desc", descFallback: "All findings with severity, asset, source, metadata.",
    icon: Database, formats: ["CSV", "JSON"], color: "#30a050", category: "operations",
    endpoint: "/api/tc/exports/findings", regions: ["eu", "us", "intl"],
    temporality: "all-time" },
];

const SECTIONS: { id: ExportCategory; titleFr: string; titleEn: string; subtitleFr: string; subtitleEn: string; icon: React.ElementType; color: string }[] = [
  { id: "incident-response", titleFr: "Réponse à incident & violation", titleEn: "Incident & Breach Response",
    subtitleFr: "Rapports légaux déclenchés par une attaque — délais 24h / 72h / 30j",
    subtitleEn: "Legal reports triggered by an attack — 24h / 72h / 30d deadlines",
    icon: Siren, color: "#e04040" },
  { id: "compliance-audit", titleFr: "Conformité & audit", titleEn: "Compliance & Audit",
    subtitleFr: "Rapports périodiques et audit rétrospectif pour direction, RSSI, auditeurs",
    subtitleEn: "Periodic and retrospective audit reports for management, CISO, auditors",
    icon: Gavel, color: "#3080d0" },
  { id: "threat-intel", titleFr: "Threat intelligence & CTI", titleEn: "Threat Intelligence & CTI",
    subtitleFr: "Snapshots temps réel pour partage avec autres SOC / alimenter firewall / EDR",
    subtitleEn: "Real-time snapshots for sharing with peer SOCs / feeding firewall / EDR",
    icon: Radio, color: "#9060d0" },
  { id: "operations", titleFr: "Opérations & inventaire", titleEn: "Operations & Inventory",
    subtitleFr: "Données brutes internes pour analyse offline",
    subtitleEn: "Internal raw data for offline analysis",
    icon: Database, color: "#30a050" },
];

type Region = "eu" | "us" | "intl";
const REGION_LABELS: Record<Region, { fr: string; en: string; flag: string }> = {
  eu: { fr: "Europe (NIS2, RGPD)", en: "Europe (NIS2, GDPR)", flag: "🇪🇺" },
  us: { fr: "États-Unis (NIST)", en: "United States (NIST)", flag: "🇺🇸" },
  intl: { fr: "International", en: "International", flag: "🌍" },
};

// ─────────────────────────────────────────────────────────
// Incident type for dropdown
// ─────────────────────────────────────────────────────────

interface IncidentOption {
  id: string;
  title: string;
  status: string;
  created_at: string;
}

// ─────────────────────────────────────────────────────────
// Date range presets
// ─────────────────────────────────────────────────────────

function presetRange(preset: string): { start: string; end: string } {
  const today = new Date();
  const end = today.toISOString().slice(0, 10);
  const d = new Date(today);
  switch (preset) {
    case "today":
      return { start: end, end };
    case "7d":
      d.setDate(d.getDate() - 7);
      return { start: d.toISOString().slice(0, 10), end };
    case "30d":
      d.setDate(d.getDate() - 30);
      return { start: d.toISOString().slice(0, 10), end };
    case "90d":
      d.setDate(d.getDate() - 90);
      return { start: d.toISOString().slice(0, 10), end };
    case "this-month": {
      const start = new Date(today.getFullYear(), today.getMonth(), 1);
      return { start: start.toISOString().slice(0, 10), end };
    }
    case "last-month": {
      const start = new Date(today.getFullYear(), today.getMonth() - 1, 1);
      const endOfLast = new Date(today.getFullYear(), today.getMonth(), 0);
      return { start: start.toISOString().slice(0, 10), end: endOfLast.toISOString().slice(0, 10) };
    }
    default:
      return { start: end, end };
  }
}

// ─────────────────────────────────────────────────────────
// Export modal — collects contextual parameters
// ─────────────────────────────────────────────────────────

interface ExportParams {
  format: string;
  locale: string;
  incident_id?: string;
  date_range?: { start: string; end: string };
  gdpr_override?: boolean;
  max_records?: number;
}

function ExportModal({
  item, format, locale, onClose, onSubmit,
}: {
  item: ExportItem;
  format: string;
  locale: string;
  onClose: () => void;
  onSubmit: (params: ExportParams) => void;
}) {
  const [incidentId, setIncidentId] = useState("");
  const [incidents, setIncidents] = useState<IncidentOption[]>([]);
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [range, setRange] = useState<{ start: string; end: string }>(() => presetRange("30d"));
  const [gdprOverride, setGdprOverride] = useState<"auto" | "yes" | "no">("auto");
  const [maxRecords, setMaxRecords] = useState(5000);

  // Load incidents when needed
  useEffect(() => {
    if (!item.requiresIncident && item.id !== "gdpr-art33") return;
    setLoadingIncidents(true);
    fetch("/api/tc/incidents?limit=50")
      .then(r => r.ok ? r.json() : { data: [] })
      .then(d => setIncidents(Array.isArray(d.data) ? d.data : []))
      .catch(() => setIncidents([]))
      .finally(() => setLoadingIncidents(false));
  }, [item.requiresIncident, item.id]);

  const needsDateRange = item.temporality === "period-bound";
  const needsIncident = item.requiresIncident;
  const offersGdpr = item.supportsGdprOverride;
  const isDataExport = item.category === "operations" || item.id === "iocs";

  const canSubmit = !needsIncident || incidentId.trim() !== "" || true; // auto-generate allowed

  const handleSubmit = () => {
    const params: ExportParams = { format: format.toLowerCase(), locale };
    if ((needsIncident || item.id === "gdpr-art33") && incidentId.trim() !== "") {
      params.incident_id = incidentId.trim();
    }
    if (needsDateRange) {
      params.date_range = range;
    }
    if (offersGdpr && gdprOverride !== "auto") {
      params.gdpr_override = gdprOverride === "yes";
    }
    if (isDataExport) {
      params.max_records = maxRecords;
    }
    onSubmit(params);
  };

  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 100,
      display: "flex", alignItems: "center", justifyContent: "center", padding: "20px",
    }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: "var(--tc-surface)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius)",
        padding: "20px", minWidth: "420px", maxWidth: "540px", width: "100%", maxHeight: "85vh", overflowY: "auto",
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <div>
            <h2 style={{ fontSize: "15px", fontWeight: 700, color: "var(--tc-text)", margin: 0 }}>
              {locale === "fr" ? "Paramètres d'export" : "Export parameters"}
            </h2>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginTop: "2px" }}>
              {item.titleFallback} — {format.toUpperCase()}
            </div>
          </div>
          <button onClick={onClose} style={{
            background: "transparent", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            padding: "4px", cursor: "pointer", color: "var(--tc-text-muted)",
          }}><X size={14} /></button>
        </div>

        {/* Legal banner */}
        {item.legal?.mandatory && (
          <div style={{
            padding: "8px 10px", background: "rgba(224,64,64,0.08)", borderLeft: "3px solid #e04040",
            borderRadius: "3px", fontSize: "10px", color: "#e04040", fontWeight: 700, marginBottom: "14px",
            display: "flex", gap: "6px", alignItems: "center",
          }}>
            <AlertTriangle size={12} />
            {locale === "fr" ? "OBLIGATION LÉGALE " : "LEGAL OBLIGATION "}
            {item.legal.region.toUpperCase()} — {item.legal.standard}
            {item.legal.deadlineHours && ` — ${locale === "fr" ? "délai" : "deadline"} ${item.legal.deadlineHours}h`}
          </div>
        )}

        {/* Incident selector */}
        {(needsIncident || item.id === "gdpr-art33") && (
          <div style={{ marginBottom: "14px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
              {locale === "fr" ? "Incident associé" : "Linked incident"}
              {needsIncident && <span style={{ color: "#e04040" }}> *</span>}
            </label>
            <select value={incidentId} onChange={e => setIncidentId(e.target.value)} style={{
              width: "100%", padding: "7px 9px", fontSize: "11px", borderRadius: "var(--tc-radius-sm)",
              background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)",
            }}>
              <option value="">
                {loadingIncidents
                  ? (locale === "fr" ? "Chargement…" : "Loading…")
                  : (locale === "fr" ? "Auto-générer depuis les alertes du jour" : "Auto-generate from today's alerts")}
              </option>
              {incidents.map(inc => (
                <option key={inc.id} value={inc.id}>{inc.id} — {inc.title}</option>
              ))}
            </select>
            {needsIncident && (
              <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "3px" }}>
                {locale === "fr"
                  ? "Sélectionne le même incident pour chaîner les 3 rapports NIS2 (early → intermediate → final)."
                  : "Pick the same incident across early/intermediate/final to chain the 3 NIS2 reports."}
              </div>
            )}
          </div>
        )}

        {/* Date range */}
        {needsDateRange && (
          <div style={{ marginBottom: "14px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
              {locale === "fr" ? "Période" : "Period"}
              <span style={{ color: "#e04040" }}> *</span>
            </label>
            <div style={{ display: "flex", gap: "4px", marginBottom: "6px", flexWrap: "wrap" }}>
              {["today", "7d", "30d", "90d", "this-month", "last-month"].map(p => (
                <button key={p} onClick={() => setRange(presetRange(p))} style={{
                  padding: "3px 8px", fontSize: "9px", fontWeight: 600, cursor: "pointer",
                  borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
                  border: "1px solid var(--tc-border)", color: "var(--tc-text-sec)",
                }}>{presetLabel(p, locale)}</button>
              ))}
            </div>
            <div style={{ display: "flex", gap: "6px" }}>
              <input type="date" value={range.start} onChange={e => setRange({ ...range, start: e.target.value })} style={dateInputStyle} />
              <span style={{ alignSelf: "center", fontSize: "10px", color: "var(--tc-text-muted)" }}>→</span>
              <input type="date" value={range.end} onChange={e => setRange({ ...range, end: e.target.value })} style={dateInputStyle} />
            </div>
          </div>
        )}

        {/* GDPR override */}
        {offersGdpr && (
          <div style={{ marginBottom: "14px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
              {locale === "fr" ? "Notification RGPD CNIL" : "GDPR/CNIL notification"}
            </label>
            <div style={{ display: "flex", gap: "4px" }}>
              {(["auto", "yes", "no"] as const).map(v => (
                <button key={v} onClick={() => setGdprOverride(v)} style={{
                  padding: "5px 10px", fontSize: "10px", fontWeight: 600, cursor: "pointer",
                  borderRadius: "var(--tc-radius-sm)",
                  background: gdprOverride === v ? "var(--tc-text)" : "var(--tc-surface-alt)",
                  color: gdprOverride === v ? "var(--tc-bg)" : "var(--tc-text-sec)",
                  border: "1px solid var(--tc-border)", flex: 1,
                }}>{gdprLabel(v, locale)}</button>
              ))}
            </div>
            <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", marginTop: "3px" }}>
              {locale === "fr"
                ? "Auto : détection par l'algorithme (PII, bases de données, exfiltration). Force yes/no si le RSSI sait mieux."
                : "Auto: algorithm detects (PII, databases, exfiltration). Force yes/no when the CISO has better context."}
            </div>
          </div>
        )}

        {/* Max records */}
        {isDataExport && (
          <div style={{ marginBottom: "14px" }}>
            <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--tc-text-sec)", display: "block", marginBottom: "4px" }}>
              {locale === "fr" ? "Limite d'enregistrements" : "Max records"}: <span style={{ color: "var(--tc-text)" }}>{maxRecords}</span>
            </label>
            <input type="range" min={100} max={10000} step={100} value={maxRecords}
              onChange={e => setMaxRecords(parseInt(e.target.value))} style={{ width: "100%" }} />
          </div>
        )}

        {/* Footer buttons */}
        <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "18px" }}>
          <button onClick={onClose} style={{
            padding: "7px 14px", fontSize: "11px", fontWeight: 600, cursor: "pointer",
            borderRadius: "var(--tc-radius-sm)", background: "var(--tc-surface-alt)",
            border: "1px solid var(--tc-border)", color: "var(--tc-text-sec)",
          }}>{locale === "fr" ? "Annuler" : "Cancel"}</button>
          <button disabled={!canSubmit} onClick={handleSubmit} style={{
            padding: "7px 14px", fontSize: "11px", fontWeight: 700, cursor: canSubmit ? "pointer" : "not-allowed",
            borderRadius: "var(--tc-radius-sm)", background: canSubmit ? item.color : "var(--tc-surface-alt)",
            color: canSubmit ? "#fff" : "var(--tc-text-muted)", border: "1px solid var(--tc-border)",
            opacity: canSubmit ? 1 : 0.5,
          }}>
            {locale === "fr" ? `Générer ${format}` : `Generate ${format}`}
          </button>
        </div>
      </div>
    </div>
  );
}

const dateInputStyle: React.CSSProperties = {
  flex: 1, padding: "6px 8px", fontSize: "11px", borderRadius: "var(--tc-radius-sm)",
  background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)",
};

function presetLabel(p: string, locale: string): string {
  if (locale === "fr") {
    return { today: "Aujourd'hui", "7d": "7 j", "30d": "30 j", "90d": "90 j",
      "this-month": "Ce mois", "last-month": "Mois dernier" }[p] || p;
  }
  return { today: "Today", "7d": "7d", "30d": "30d", "90d": "90d",
    "this-month": "This month", "last-month": "Last month" }[p] || p;
}

function gdprLabel(v: string, locale: string): string {
  if (locale === "fr") return { auto: "Auto", yes: "Forcer oui", no: "Forcer non" }[v] || v;
  return { auto: "Auto", yes: "Force yes", no: "Force no" }[v] || v;
}

// ─────────────────────────────────────────────────────────
// Badges (visible on export cards)
// ─────────────────────────────────────────────────────────

function Badge({ label, color, icon: Icon }: { label: string; color: string; icon?: React.ElementType }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "3px",
      padding: "1px 6px", fontSize: "8px", fontWeight: 700,
      borderRadius: "3px", background: `${color}18`, color,
      border: `1px solid ${color}30`, textTransform: "uppercase", letterSpacing: "0.05em",
    }}>
      {Icon && <Icon size={8} />}
      {label}
    </span>
  );
}

function exportBadges(item: ExportItem, locale: string): React.ReactNode[] {
  const out: React.ReactNode[] = [];
  if (item.legal?.mandatory) {
    const label = item.legal.deadlineHours
      ? (locale === "fr" ? `Légal ${item.legal.deadlineHours}h` : `Legal ${item.legal.deadlineHours}h`)
      : (locale === "fr" ? "Obligation légale" : "Legal obligation");
    out.push(<Badge key="legal" label={label} color="#e04040" icon={AlertTriangle} />);
  }
  if (item.frequency === "real-time") {
    out.push(<Badge key="freq" label={locale === "fr" ? "Temps réel" : "Real-time"} color="#3080d0" icon={Radio} />);
  } else if (item.frequency === "monthly") {
    out.push(<Badge key="freq" label={locale === "fr" ? "Mensuel" : "Monthly"} color="#9060d0" icon={Clock} />);
  } else if (item.frequency === "annual") {
    out.push(<Badge key="freq" label={locale === "fr" ? "Annuel" : "Annual"} color="#9060d0" icon={Clock} />);
  }
  if (item.requiresIncident) {
    out.push(<Badge key="inc" label={locale === "fr" ? "Incident requis" : "Incident req."} color="#d06020" />);
  }
  if (item.temporality === "period-bound") {
    out.push(<Badge key="per" label={locale === "fr" ? "Période" : "Period"} color="#606060" />);
  }
  return out;
}

// ─────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────

export default function ExportsPage() {
  const locale = useLocale();
  const [generating, setGenerating] = useState<string | null>(null);
  const [generated, setGenerated] = useState<string | null>(null);
  const [region, setRegion] = useState<Region>("eu");
  const [modalItem, setModalItem] = useState<{ item: ExportItem; format: string } | null>(null);

  useEffect(() => {
    fetch("/api/tc/config?key=tc_config_company").then(r => r.json()).then(d => {
      const geo = d.tc_config_company?.geo_scope || "";
      if (geo.includes("america") || geo === "us") setRegion("us");
      else if (geo === "international") setRegion("intl");
      else setRegion("eu");
    }).catch(() => {});
  }, []);

  const isRecommended = (item: ExportItem) => item.regions.includes(region);
  const getTitle = (item: ExportItem) => {
    const translated = tr(item.titleKey, locale);
    return translated !== item.titleKey ? translated : item.titleFallback;
  };
  const getDesc = (item: ExportItem) => {
    const translated = tr(item.descKey, locale);
    return translated !== item.descKey ? translated : item.descFallback;
  };

  const needsModal = (item: ExportItem): boolean => {
    return item.temporality === "period-bound"
      || item.requiresIncident === true
      || item.supportsGdprOverride === true
      || item.category === "operations"
      || item.id === "iocs";
  };

  const handleExportClick = (item: ExportItem, format: string) => {
    if (needsModal(item)) {
      setModalItem({ item, format });
      return;
    }
    runExport(item, { format: format.toLowerCase(), locale });
  };

  const runExport = async (item: ExportItem, params: ExportParams) => {
    setGenerating(item.id);
    setGenerated(null);
    setModalItem(null);
    try {
      const res = await fetch(item.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(params),
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => tr("serverError", locale));
        alert(text || tr("generationError", locale));
        setGenerating(null);
        return;
      }

      const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const fmt = params.format;
      let blob: Blob;
      let filename: string;

      if (fmt === "pdf") {
        const cd = res.headers.get("Content-Disposition");
        const bytes = await res.arrayBuffer();
        blob = new Blob([bytes], { type: "application/pdf" });
        const match = cd?.match(/filename="?([^"]+)"?/);
        filename = match?.[1] || `threatclaw_${item.id}_${date}.pdf`;
      } else if (fmt === "csv") {
        const data = await res.json();
        const rows = data.data || [];
        if (rows.length === 0) {
          blob = new Blob([""], { type: "text/csv" });
        } else {
          const headers = Object.keys(rows[0]);
          const csv = [headers.join(","), ...rows.map((r: Record<string, unknown>) =>
            headers.map(h => JSON.stringify(r[h] ?? "")).join(","))].join("\n");
          blob = new Blob([csv], { type: "text/csv" });
        }
        filename = `threatclaw_${item.id}_${date}.csv`;
      } else {
        const data = await res.json();
        blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        filename = `threatclaw_${item.id}_${date}.json`;
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);

      setGenerated(item.id);
      setTimeout(() => setGenerated(null), 3000);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "timeout";
      alert((locale === "fr" ? "Erreur : " : "Error: ") + msg);
    }
    setGenerating(null);
  };

  const sectionItems = useMemo(() => {
    const map: Record<ExportCategory, ExportItem[]> = {
      "incident-response": [], "compliance-audit": [], "threat-intel": [], "operations": [],
    };
    for (const e of EXPORTS) {
      map[e.category].push(e);
    }
    // Recommended first
    for (const k of Object.keys(map) as ExportCategory[]) {
      map[k].sort((a, b) => {
        const ar = isRecommended(a) ? 0 : 1;
        const br = isRecommended(b) ? 0 : 1;
        return ar - br;
      });
    }
    return map;
  }, [region]);

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>
            {locale === "fr" ? "Rapports & Exports" : "Reports & Exports"}
          </h1>
          <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
            {locale === "fr"
              ? "4 familles : réponse à incident · conformité & audit · threat intel · opérations"
              : "4 families: incident response · compliance & audit · threat intel · operations"}
          </p>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
          {(Object.entries(REGION_LABELS) as [Region, typeof REGION_LABELS["eu"]][]).map(([key, val]) => (
            <button key={key} onClick={() => setRegion(key)} style={{
              padding: "6px 10px", fontSize: "10px", fontWeight: 600, borderRadius: "6px", cursor: "pointer",
              background: region === key ? "var(--tc-surface-alt)" : "transparent",
              border: region === key ? "1px solid var(--tc-border)" : "1px solid transparent",
              color: region === key ? "var(--tc-text)" : "var(--tc-text-muted)",
              display: "flex", alignItems: "center", gap: "4px",
            }}>
              <span>{val.flag}</span>
              {locale === "fr" ? val.fr.split(" (")[0] : val.en.split(" (")[0]}
            </button>
          ))}
        </div>
      </div>

      {SECTIONS.map(section => {
        const items = sectionItems[section.id];
        if (items.length === 0) return null;
        const SectionIcon = section.icon;
        return (
          <div key={section.id} style={{ marginBottom: "28px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
              <SectionIcon size={16} color={section.color} />
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {locale === "fr" ? section.titleFr : section.titleEn}
              </div>
            </div>
            <div style={{ fontSize: "11px", color: "var(--tc-text-muted)", marginBottom: "10px", marginLeft: "24px" }}>
              {locale === "fr" ? section.subtitleFr : section.subtitleEn}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
              {items.map(item => {
                const Icon = item.icon;
                const isGenerating = generating === item.id;
                const isGenerated = generated === item.id;
                const rec = isRecommended(item);
                const badges = exportBadges(item, locale);

                return (
                  <NeuCard key={item.id} style={{ padding: "14px", opacity: rec ? 1 : 0.55, transition: "opacity 0.2s" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
                      <div style={{
                        width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)", flexShrink: 0,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        background: `${item.color}12`, border: `1px solid ${item.color}25`,
                      }}>
                        <Icon size={15} color={item.color} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "3px", flexWrap: "wrap" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{getTitle(item)}</span>
                          {rec && <Star size={10} color="#d0a820" fill="#d0a820" />}
                        </div>

                        {badges.length > 0 && (
                          <div style={{ display: "flex", gap: "3px", flexWrap: "wrap", marginBottom: "5px" }}>
                            {badges}
                          </div>
                        )}

                        <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", lineHeight: "1.4", marginBottom: "8px" }}>
                          {getDesc(item)}
                        </div>

                        <div style={{ display: "flex", gap: "4px" }}>
                          {item.formats.map(fmt => (
                            <button key={fmt} onClick={() => handleExportClick(item, fmt)} disabled={isGenerating}
                              style={{
                                padding: "3px 10px", fontSize: "9px", fontWeight: 700, fontFamily: "inherit",
                                borderRadius: "var(--tc-radius-sm)", cursor: isGenerating ? "default" : "pointer",
                                background: isGenerated ? "rgba(48,160,80,0.1)" : "var(--tc-input)",
                                color: isGenerated ? "#30a050" : "var(--tc-text-sec)",
                                border: isGenerated ? "1px solid rgba(48,160,80,0.2)" : "1px solid var(--tc-border)",
                                display: "flex", alignItems: "center", gap: "3px",
                                textTransform: "uppercase", letterSpacing: "0.05em",
                              }}>
                              {isGenerating
                                ? <Loader2 size={9} className="animate-spin" />
                                : isGenerated ? <CheckCircle2 size={9} /> : <Download size={9} />}
                              {fmt}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  </NeuCard>
                );
              })}
            </div>
          </div>
        );
      })}

      {modalItem && (
        <ExportModal
          item={modalItem.item}
          format={modalItem.format}
          locale={locale}
          onClose={() => setModalItem(null)}
          onSubmit={params => runExport(modalItem.item, params)}
        />
      )}
    </div>
  );
}
