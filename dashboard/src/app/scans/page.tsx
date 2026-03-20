"use client";

import React from "react";
import Header from "@/components/Header";

const scans = [
  { name: "Scan vulnérabilités", status: "completed", last: "Aujourd'hui 02:15", next: "Demain 02:00", findings: 4 },
  { name: "Analyse logs SOC", status: "running", last: "Il y a 3 min", next: "Dans 2 min", findings: 12 },
  { name: "Surveillance dark web", status: "completed", last: "Aujourd'hui 06:00", next: "12:00", findings: 0 },
  { name: "Audit cloud", status: "scheduled", last: "Lundi 03:00", next: "Lundi prochain 03:00", findings: 3 },
  { name: "Campagne phishing", status: "scheduled", last: "01/03/2026", next: "01/04/2026", findings: 0 },
  { name: "Rapport hebdomadaire", status: "completed", last: "Vendredi 08:00", next: "Vendredi 08:00", findings: 0 },
];

const statusMap: Record<string, { label: string; color: string }> = {
  completed: { label: "Terminé", color: "var(--accent-ok)" },
  running: { label: "En cours", color: "var(--accent-warning)" },
  scheduled: { label: "Planifié", color: "var(--text-muted)" },
};

export default function ScansPage() {
  return (
    <div>
      <Header subtitle="Scans & Routines" />
      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {scans.map((scan) => {
          const st = statusMap[scan.status];
          return (
            <div key={scan.name} className="pit" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-primary)" }}>{scan.name}</div>
                <div style={{ fontSize: "9px", color: "var(--text-muted)", marginTop: "2px" }}>
                  Dernier : {scan.last} · Prochain : {scan.next}
                </div>
              </div>
              {scan.findings > 0 && (
                <span style={{ fontSize: "11px", fontWeight: 800, color: "var(--accent-danger)" }}>
                  {scan.findings}
                </span>
              )}
              <span style={{
                fontSize: "8px",
                fontWeight: 700,
                color: st.color,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
              }}>
                {st.label}
              </span>
              <button className="btn-raised" style={{ padding: "4px 8px" }}>
                {scan.status === "running" ? "Stop" : "Lancer"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
