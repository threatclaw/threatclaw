"use client";

import React, { useState } from "react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";
import { NeuCard } from "@/components/chrome/NeuCard";
import {
  FileText, Shield, Download, Clock, Globe, Database,
  AlertTriangle, Server, Loader2, CheckCircle2, Lock,
  BarChart3, Users, Eye,
} from "lucide-react";

interface ExportItem {
  id: string;
  title: string;
  description: string;
  icon: React.ElementType;
  formats: string[];
  color: string;
  tier: string;
  endpoint: string;
}

const EXPORTS: ExportItem[] = [
  // Tier 1 — Réglementaire NIS2
  { id: "nis2-early", title: "Rapport NIS2 — Early Warning (24h)", description: "Notification initiale obligatoire. Nature de l'incident, systèmes affectés, mesures immédiates.", icon: Clock, formats: ["PDF", "JSON"], color: "#e04040", tier: "reglementaire", endpoint: "/api/tc/exports/nis2-early-warning" },
  { id: "nis2-intermediate", title: "Rapport NIS2 — Intermédiaire (72h)", description: "Analyse préliminaire des causes, IOCs identifiés, actions correctives en cours.", icon: FileText, formats: ["PDF", "JSON"], color: "#e04040", tier: "reglementaire", endpoint: "/api/tc/exports/nis2-intermediate" },
  { id: "nis2-final", title: "Rapport NIS2 — Final (1 mois)", description: "Analyse complète post-incident, root cause, timeline, recommandations.", icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", tier: "reglementaire", endpoint: "/api/tc/exports/nis2-final" },
  { id: "nis2-art21", title: "Conformité NIS2 Article 21", description: "Checklist des 10 mesures obligatoires avec score et preuves par mesure.", icon: Lock, formats: ["PDF", "JSON"], color: "#d06020", tier: "reglementaire", endpoint: "/api/tc/exports/nis2-article21" },
  { id: "gdpr-art33", title: "RGPD — Notification CNIL (Art. 33)", description: "Violation de données personnelles. Nature, personnes concernées, mesures prises.", icon: Shield, formats: ["PDF", "JSON"], color: "#e04040", tier: "reglementaire", endpoint: "/api/tc/exports/gdpr-article33" },
  { id: "nist-incident", title: "NIST SP 800-61 — Incident Report", description: "Format NIST CSF 2.0. Compatible agences fédérales US et standard international.", icon: Globe, formats: ["PDF", "JSON"], color: "#d06020", tier: "reglementaire", endpoint: "/api/tc/exports/nist-incident" },
  { id: "iso27001", title: "ISO 27001 — Rapport d'incident", description: "Contrôles A.5.24-A.5.28. Classification, réponse, preuves, leçons apprises.", icon: Lock, formats: ["PDF", "JSON"], color: "#d06020", tier: "reglementaire", endpoint: "/api/tc/exports/iso27001-incident" },

  // Tier 2 — Opérationnel
  { id: "executive", title: "Rapport exécutif — Direction", description: "Score sécurité, incidents du mois, risques business. Langage non-technique pour le COMEX.", icon: BarChart3, formats: ["PDF"], color: "#3080d0", tier: "operationnel", endpoint: "/api/tc/exports/executive-report" },
  { id: "technical", title: "Rapport technique — RSSI", description: "Tous les findings, CVEs, TTPs MITRE, recommandations détaillées.", icon: FileText, formats: ["PDF"], color: "#3080d0", tier: "operationnel", endpoint: "/api/tc/exports/technical-report" },
  { id: "audit-trail", title: "Journal d'audit", description: "Toutes les actions ThreatClaw. Preuve légale horodatée en cas d'incident.", icon: Eye, formats: ["PDF", "JSON"], color: "#3080d0", tier: "operationnel", endpoint: "/api/tc/exports/audit-trail" },

  // Tier 3 — Technique
  { id: "stix2", title: "STIX 2.1 Bundle", description: "Graph d'attaque complet. Compatible OpenCTI, MISP, Splunk, QRadar.", icon: Globe, formats: ["JSON"], color: "#9060d0", tier: "technique", endpoint: "/api/tc/exports/stix2" },
  { id: "misp", title: "MISP Event", description: "Standard de partage threat intel. Compatible CERTs nationaux.", icon: Users, formats: ["JSON"], color: "#9060d0", tier: "technique", endpoint: "/api/tc/exports/misp-event" },
  { id: "iocs", title: "Indicateurs de compromission (IOCs)", description: "IPs malveillantes, hashes, domaines suspects. Importable dans firewall/EDR.", icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#9060d0", tier: "technique", endpoint: "/api/tc/exports/iocs" },
  { id: "assets-csv", title: "Assets — Inventaire", description: "Liste complète des assets avec catégorie, criticité, IP, OS.", icon: Server, formats: ["CSV", "JSON"], color: "#30a050", tier: "technique", endpoint: "/api/tc/exports/assets" },
  { id: "alerts-csv", title: "Alertes de sécurité", description: "Toutes les alertes Sigma avec niveau, source, timestamps.", icon: AlertTriangle, formats: ["CSV", "JSON"], color: "#30a050", tier: "technique", endpoint: "/api/tc/exports/alerts" },
  { id: "findings-csv", title: "Vulnérabilités (Findings)", description: "Tous les findings avec sévérité, asset, source, metadata.", icon: Database, formats: ["CSV", "JSON"], color: "#30a050", tier: "technique", endpoint: "/api/tc/exports/findings" },
];

const SECTIONS = [
  { id: "reglementaire", titleKey: "regulatoryReports", subtitle: "NIS2, RGPD, NIST, ISO 27001", icon: Shield, color: "#e04040" },
  { id: "operationnel", titleKey: "operationalReports", subtitle: "Direction, RSSI, audit", icon: BarChart3, color: "#3080d0" },
  { id: "technique", titleKey: "technicalExports", subtitle: "STIX, MISP, CSV — SIEM, EDR", icon: Database, color: "#9060d0" },
];

export default function ExportsPage() {
  const locale = useLocale();
  const [generating, setGenerating] = useState<string | null>(null);
  const [generated, setGenerated] = useState<string | null>(null);

  const handleExport = async (item: ExportItem, format: string) => {
    setGenerating(item.id);
    setGenerated(null);

    try {
      const res = await fetch(item.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ format: format.toLowerCase() }),
        signal: AbortSignal.timeout(30000),
      });

      if (!res.ok) {
        const text = await res.text().catch(() => tr("serverError", locale));
        alert(text || "Erreur lors de la génération");
        setGenerating(null);
        return;
      }

      const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
      const isPdf = format.toLowerCase() === "pdf";
      const isCsv = format.toLowerCase() === "csv";

      let blob: Blob;
      let filename: string;

      if (isPdf) {
        // PDF → binary download
        const contentDisposition = res.headers.get("Content-Disposition");
        const bytes = await res.arrayBuffer();
        blob = new Blob([bytes], { type: "application/pdf" });
        // Extract filename from Content-Disposition header or generate one
        const match = contentDisposition?.match(/filename="?([^"]+)"?/);
        filename = match?.[1] || `threatclaw_${item.id}_${date}.pdf`;
      } else if (isCsv) {
        const data = await res.json();
        // Convert JSON array to CSV
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
        // JSON
        const data = await res.json();
        blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        filename = `threatclaw_${item.id}_${data.company_name || "threatclaw"}_${date}.json`;
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
      alert("Erreur: " + (e.message || "timeout"));
    }
    setGenerating(null);
  };

  return (
    <div>
      <div style={{ marginBottom: "24px" }}>
        <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", letterSpacing: "-0.02em", margin: 0 }}>Rapports & Exports</h1>
        <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
          Rapports NIS2 automatiques, exports STIX/MISP, CSV pour vos outils
        </p>
      </div>

      {SECTIONS.map(section => {
        const items = EXPORTS.filter(e => e.tier === section.id);
        const SectionIcon = section.icon;
        return (
          <div key={section.id} style={{ marginBottom: "24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
              <SectionIcon size={16} color={section.color} />
              <div>
                <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr(section.titleKey, locale)}</div>
                <div style={{ fontSize: "10px", color: "var(--tc-text-muted)" }}>{section.subtitle}</div>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
              {items.map(item => {
                const Icon = item.icon;
                const isGenerating = generating === item.id;
                const isGenerated = generated === item.id;

                return (
                  <NeuCard key={item.id} style={{ padding: "14px" }}>
                    <div style={{ display: "flex", alignItems: "flex-start", gap: "10px" }}>
                      <div style={{
                        width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)", flexShrink: 0,
                        display: "flex", alignItems: "center", justifyContent: "center",
                        background: `${item.color}12`, border: `1px solid ${item.color}25`,
                      }}>
                        <Icon size={15} color={item.color} />
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--tc-text)", marginBottom: "2px" }}>{item.title}</div>
                        <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", lineHeight: "1.4", marginBottom: "8px" }}>{item.description}</div>
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
