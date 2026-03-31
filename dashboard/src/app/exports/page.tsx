"use client";

import React, { useState, useEffect } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import {
  FileText, Shield, Download, Clock, Globe, Database,
  AlertTriangle, Server, Loader2, CheckCircle2, Lock,
  BarChart3, Users, Eye, Star, ChevronDown,
} from "lucide-react";

interface ExportItem {
  id: string;
  titleKey: string; // i18n key for title
  titleFallback: string; // fallback if key not in i18n
  descKey: string;
  descFallback: string;
  icon: React.ElementType;
  formats: string[];
  color: string;
  tier: string;
  endpoint: string;
  // Which regions recommend this report
  regions: ("eu" | "us" | "intl")[];
  // Which sectors especially need this
  sectors?: string[];
}

const EXPORTS: ExportItem[] = [
  // Regulatory — EU
  { id: "nis2-early", titleKey: "export_nis2_early", titleFallback: "NIS2 — Early Warning (24h)", descKey: "export_nis2_early_desc", descFallback: "Initial mandatory notification. Incident nature, affected systems, immediate measures.", icon: Clock, formats: ["PDF", "JSON"], color: "#e04040", tier: "regulatory", endpoint: "/api/tc/exports/nis2-early-warning", regions: ["eu"] },
  { id: "nis2-intermediate", titleKey: "export_nis2_inter", titleFallback: "NIS2 — Intermediate (72h)", descKey: "export_nis2_inter_desc", descFallback: "Preliminary cause analysis, identified IOCs, corrective actions in progress.", icon: FileText, formats: ["PDF", "JSON"], color: "#e04040", tier: "regulatory", endpoint: "/api/tc/exports/nis2-intermediate", regions: ["eu"] },
  { id: "nis2-final", titleKey: "export_nis2_final", titleFallback: "NIS2 — Final Report (1 month)", descKey: "export_nis2_final_desc", descFallback: "Complete post-incident analysis, root cause, timeline, recommendations.", icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", tier: "regulatory", endpoint: "/api/tc/exports/nis2-final", regions: ["eu"] },
  { id: "nis2-art21", titleKey: "export_nis2_art21", titleFallback: "NIS2 Article 21 Compliance", descKey: "export_nis2_art21_desc", descFallback: "Checklist of 10 mandatory measures with score and evidence per measure.", icon: Lock, formats: ["PDF", "JSON"], color: "#d06020", tier: "regulatory", endpoint: "/api/tc/exports/nis2-article21", regions: ["eu"] },
  { id: "gdpr-art33", titleKey: "export_gdpr", titleFallback: "GDPR — Data Breach (Art. 33)", descKey: "export_gdpr_desc", descFallback: "Personal data breach notification. Nature, persons affected, measures taken.", icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", tier: "regulatory", endpoint: "/api/tc/exports/gdpr-article33", regions: ["eu"] },
  // Regulatory — US / International
  { id: "nist-incident", titleKey: "export_nist", titleFallback: "NIST SP 800-61 — Incident Report", descKey: "export_nist_desc", descFallback: "NIST CSF 2.0 format. Compatible with US federal agencies and international standards.", icon: Globe, formats: ["PDF", "JSON"], color: "#d06020", tier: "regulatory", endpoint: "/api/tc/exports/nist-incident", regions: ["us", "intl"] },
  { id: "iso27001", titleKey: "export_iso27001", titleFallback: "ISO 27001 — Incident Report", descKey: "export_iso27001_desc", descFallback: "Controls A.5.24-A.5.28. Classification, response, evidence, lessons learned.", icon: Lock, formats: ["PDF", "JSON"], color: "#d06020", tier: "regulatory", endpoint: "/api/tc/exports/iso27001-incident", regions: ["eu", "us", "intl"] },

  // Operational
  { id: "executive", titleKey: "export_executive", titleFallback: "Executive Report", descKey: "export_executive_desc", descFallback: "Security score, monthly incidents, business risks. Non-technical language for management.", icon: BarChart3, formats: ["PDF"], color: "#3080d0", tier: "operational", endpoint: "/api/tc/exports/executive-report", regions: ["eu", "us", "intl"] },
  { id: "technical", titleKey: "export_technical", titleFallback: "Technical Report", descKey: "export_technical_desc", descFallback: "All findings, CVEs, MITRE ATT&CK TTPs, detailed recommendations.", icon: FileText, formats: ["PDF"], color: "#3080d0", tier: "operational", endpoint: "/api/tc/exports/technical-report", regions: ["eu", "us", "intl"] },
  { id: "audit-trail", titleKey: "export_audit", titleFallback: "Audit Trail", descKey: "export_audit_desc", descFallback: "All ThreatClaw actions. Timestamped legal evidence for incidents.", icon: Eye, formats: ["PDF", "JSON"], color: "#3080d0", tier: "operational", endpoint: "/api/tc/exports/audit-trail", regions: ["eu", "us", "intl"] },

  // Technical
  { id: "stix2", titleKey: "export_stix", titleFallback: "STIX 2.1 Bundle", descKey: "export_stix_desc", descFallback: "Full attack graph. Compatible with OpenCTI, MISP, Splunk, QRadar.", icon: Globe, formats: ["JSON"], color: "#9060d0", tier: "technical", endpoint: "/api/tc/exports/stix2", regions: ["eu", "us", "intl"] },
  { id: "misp", titleKey: "export_misp", titleFallback: "MISP Event", descKey: "export_misp_desc", descFallback: "Threat intel sharing standard. Compatible with national CERTs.", icon: Users, formats: ["JSON"], color: "#9060d0", tier: "technical", endpoint: "/api/tc/exports/misp-event", regions: ["eu", "us", "intl"] },
  { id: "iocs", titleKey: "export_iocs", titleFallback: "IOCs (Indicators of Compromise)", descKey: "export_iocs_desc", descFallback: "Malicious IPs, hashes, suspicious domains. Importable into firewall/EDR.", icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#9060d0", tier: "technical", endpoint: "/api/tc/exports/iocs", regions: ["eu", "us", "intl"] },
  { id: "assets-csv", titleKey: "export_assets", titleFallback: "Assets Inventory", descKey: "export_assets_desc", descFallback: "Complete asset list with category, criticality, IP, OS.", icon: Server, formats: ["CSV", "JSON"], color: "#30a050", tier: "technical", endpoint: "/api/tc/exports/assets", regions: ["eu", "us", "intl"] },
  { id: "alerts-csv", titleKey: "export_alerts", titleFallback: "Security Alerts", descKey: "export_alerts_desc", descFallback: "All Sigma alerts with level, source, timestamps.", icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#30a050", tier: "technical", endpoint: "/api/tc/exports/alerts", regions: ["eu", "us", "intl"] },
  { id: "findings-csv", titleKey: "export_findings", titleFallback: "Vulnerabilities (Findings)", descKey: "export_findings_desc", descFallback: "All findings with severity, asset, source, metadata.", icon: Database, formats: ["CSV", "JSON"], color: "#30a050", tier: "technical", endpoint: "/api/tc/exports/findings", regions: ["eu", "us", "intl"] },
];

const SECTIONS = [
  { id: "regulatory", titleKey: "regulatoryReports", icon: Shield, color: "#e04040" },
  { id: "operational", titleKey: "operationalReports", icon: BarChart3, color: "#3080d0" },
  { id: "technical", titleKey: "technicalExports", icon: Database, color: "#9060d0" },
];

type Region = "eu" | "us" | "intl";
const REGION_LABELS: Record<Region, { fr: string; en: string; flag: string }> = {
  eu: { fr: "Europe (NIS2, RGPD)", en: "Europe (NIS2, GDPR)", flag: "🇪🇺" },
  us: { fr: "États-Unis (NIST)", en: "United States (NIST)", flag: "🇺🇸" },
  intl: { fr: "International", en: "International", flag: "🌍" },
};

export default function ExportsPage() {
  const locale = useLocale();
  const [generating, setGenerating] = useState<string | null>(null);
  const [generated, setGenerated] = useState<string | null>(null);
  const [region, setRegion] = useState<Region>("eu");

  // Auto-detect from company profile
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
    // Try i18n key first, fallback to hardcoded
    const translated = tr(item.titleKey, locale);
    return translated !== item.titleKey ? translated : item.titleFallback;
  };

  const getDesc = (item: ExportItem) => {
    const translated = tr(item.descKey, locale);
    return translated !== item.descKey ? translated : item.descFallback;
  };

  const handleExport = async (item: ExportItem, format: string) => {
    setGenerating(item.id);
    setGenerated(null);

    try {
      const res = await fetch(item.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: format.toLowerCase(), locale }),
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => tr("serverError", locale));
        alert(text || tr("generationError", locale));
        setGenerating(null);
        return;
      }

      const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const isPdf = format.toLowerCase() === "pdf";
      const isCsv = format.toLowerCase() === "csv";

      let blob: Blob;
      let filename: string;

      if (isPdf) {
        const contentDisposition = res.headers.get("Content-Disposition");
        const bytes = await res.arrayBuffer();
        blob = new Blob([bytes], { type: "application/pdf" });
        const match = contentDisposition?.match(/filename="?([^"]+)"?/);
        filename = match?.[1] || `threatclaw_${item.id}_${date}.pdf`;
      } else if (isCsv) {
        const data = await res.json();
        const rows = data.data || [];
        if (rows.length === 0) {
          blob = new Blob([""], { type: "text/csv" });
        } else {
          const headers = Object.keys(rows[0]);
          const csv = [headers.join(","), ...rows.map((r: Record<string, unknown>) => headers.map(h => JSON.stringify(r[h] ?? "")).join(","))].join("\n");
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
    } catch (e: any) {
      alert((locale === "fr" ? "Erreur : " : "Error: ") + (e.message || "timeout"));
    }
    setGenerating(null);
  };

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "24px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>
            {locale === "fr" ? "Rapports & Exports" : "Reports & Exports"}
          </h1>
          <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
            {locale === "fr" ? "Rapports réglementaires, exports STIX/MISP, CSV" : "Regulatory reports, STIX/MISP exports, CSV"}
          </p>
        </div>

        {/* Region selector */}
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
        // Sort: recommended first, then others
        const allItems = EXPORTS.filter(e => e.tier === section.id);
        const recommended = allItems.filter(e => isRecommended(e));
        const others = allItems.filter(e => !isRecommended(e));
        const sorted = [...recommended, ...others];

        if (sorted.length === 0) return null;
        const SectionIcon = section.icon;

        return (
          <div key={section.id} style={{ marginBottom: "24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
              <SectionIcon size={16} color={section.color} />
              <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {tr(section.titleKey, locale)}
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
              {sorted.map(item => {
                const Icon = item.icon;
                const isGenerating = generating === item.id;
                const isGenerated = generated === item.id;
                const rec = isRecommended(item);

                return (
                  <NeuCard key={item.id} style={{ padding: "14px", opacity: rec ? 1 : 0.6, transition: "opacity 0.2s" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
                      <div style={{
                        width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)", flexShrink: 0,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        background: `${item.color}12`, border: `1px solid ${item.color}25`,
                      }}>
                        <Icon size={15} color={item.color} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "2px" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)" }}>{getTitle(item)}</span>
                          {rec && <Star size={10} color="#d0a820" fill="#d0a820" />}
                        </div>
                        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", lineHeight: "1.4", marginBottom: "8px" }}>{getDesc(item)}</div>
                        <div style={{ display: "flex", gap: "4px" }}>
                          {item.formats.map(fmt => (
                            <button key={fmt} onClick={() => handleExport(item, fmt)} disabled={isGenerating}
                              style={{
                                padding: "3px 10px", fontSize: "9px", fontWeight: 700, fontFamily: "inherit",
                                borderRadius: "var(--tc-radius-sm)", cursor: isGenerating ? "default" : "pointer",
                                background: isGenerated ? "rgba(48,160,80,0.1)" : "var(--tc-input)",
                                color: isGenerated ? "#30a050" : "var(--tc-text-sec)",
                                border: isGenerated ? "1px solid rgba(48,160,80,0.2)" : "1px solid var(--tc-border)",
                                display: "flex", alignItems: "center", gap: "3px",
                                textTransform: "uppercase", letterSpacing: "0.05em",
                              }}>
                              {isGenerating ? <Loader2 size={9} className="animate-spin" /> : isGenerated ? <CheckCircle2 size={9} /> : <Download size={9} />}
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
    </div>
  );
}
