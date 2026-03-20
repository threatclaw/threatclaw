"use client";

import React from "react";
import { X, Plus } from "lucide-react";

export interface WidgetDef {
  id: string;
  title: string;
  description: string;
  category: string;
  defaultSize: { w: number; h: number };
}

const ALL_WIDGETS: WidgetDef[] = [
  { id: "score", title: "Score Global", description: "Jauge de score sécurité", category: "Vue d'ensemble", defaultSize: { w: 1, h: 2 } },
  { id: "pillars", title: "Piliers Sécurité", description: "Barres par domaine", category: "Vue d'ensemble", defaultSize: { w: 2, h: 2 } },
  { id: "stats", title: "Statistiques", description: "Métriques clés en 4 colonnes", category: "Vue d'ensemble", defaultSize: { w: 4, h: 1 } },
  { id: "alerts", title: "Alertes SOC", description: "Dernières alertes de sécurité", category: "Monitoring", defaultSize: { w: 4, h: 2 } },
  { id: "vulns", title: "Vulnérabilités", description: "Répartition par sévérité", category: "Scanning", defaultSize: { w: 2, h: 2 } },
  { id: "nis2", title: "Conformité NIS2", description: "Score par article Art.21", category: "Conformité", defaultSize: { w: 2, h: 2 } },
  { id: "cloud", title: "Posture Cloud", description: "Score et tendance cloud", category: "Infrastructure", defaultSize: { w: 2, h: 1 } },
  { id: "darkweb", title: "Dark Web", description: "Statut surveillance fuites", category: "Monitoring", defaultSize: { w: 1, h: 1 } },
  { id: "phishing", title: "Phishing", description: "Résultats dernière campagne", category: "Sensibilisation", defaultSize: { w: 2, h: 1 } },
  { id: "reports", title: "Rapports", description: "Derniers rapports générés", category: "Rapports", defaultSize: { w: 2, h: 2 } },
];

interface WidgetDrawerProps {
  open: boolean;
  onClose: () => void;
  activeWidgets: string[];
  onAdd: (widget: WidgetDef) => void;
}

export default function WidgetDrawer({ open, onClose, activeWidgets, onAdd }: WidgetDrawerProps) {
  if (!open) return null;

  const categories = Array.from(new Set(ALL_WIDGETS.map((w) => w.category)));
  const available = ALL_WIDGETS.filter((w) => !activeWidgets.includes(w.id));

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 100,
        background: "rgba(0,0,0,0.5)",
        backdropFilter: "blur(4px)",
        display: "flex",
        justifyContent: "flex-end",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "320px",
          background: "var(--bg-base)",
          borderLeft: "1px solid var(--border-subtle)",
          padding: "16px",
          overflowY: "auto",
        }}
        onClick={(e) => e.stopPropagation()}
        className="scrollbar-thin"
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
          <span style={{ fontSize: "11px", fontWeight: 800, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--text-logo)" }}>
            Ajouter un widget
          </span>
          <button onClick={onClose} className="btn-raised" style={{ padding: "4px" }}>
            <X size={12} color="var(--text-secondary)" />
          </button>
        </div>

        {available.length === 0 && (
          <div className="pit-sm" style={{ textAlign: "center" }}>
            <p style={{ fontSize: "10px", color: "var(--text-muted)" }}>
              Tous les widgets sont déjà affichés
            </p>
          </div>
        )}

        {categories.map((cat) => {
          const catWidgets = available.filter((w) => w.category === cat);
          if (catWidgets.length === 0) return null;
          return (
            <div key={cat} style={{ marginBottom: "12px" }}>
              <div className="label-caps" style={{ marginBottom: "6px" }}>{cat}</div>
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                {catWidgets.map((w) => (
                  <div key={w.id} className="pit-sm" style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    cursor: "pointer",
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-primary)" }}>
                        {w.title}
                      </div>
                      <div style={{ fontSize: "9px", color: "var(--text-secondary)" }}>
                        {w.description}
                      </div>
                    </div>
                    <button
                      className="btn-raised"
                      onClick={() => onAdd(w)}
                      style={{ padding: "4px 8px", display: "flex", alignItems: "center", gap: "3px" }}
                    >
                      <Plus size={10} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
