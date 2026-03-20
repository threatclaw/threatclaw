"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { Plus, Server, Shield, Wifi, Monitor, Trash2, CheckCircle2, AlertTriangle } from "lucide-react";

interface Target {
  id: string;
  host: string;
  target_type: string;
  access_type: string;
  port: number;
  mode: string;
  credential_name: string | null;
  ssh_host_key: string | null;
  driver: string | null;
  allowed_actions: string[];
  tags: string[];
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  linux: Server, windows: Monitor, firewall: Shield, local: Server,
};

const TYPE_LABELS: Record<string, string> = {
  linux: "Linux", windows: "Windows", firewall: "Firewall", network: "Réseau", local: "Local",
};

export default function InfrastructurePage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [newTarget, setNewTarget] = useState({
    id: "", host: "", target_type: "linux", access_type: "ssh", port: "22", mode: "investigator",
    credential_name: "", driver: "",
  });

  const loadTargets = async () => {
    try {
      const res = await fetch("/api/tc/targets");
      const data = await res.json();
      setTargets(data.targets || []);
    } catch { /* */ }
  };

  useEffect(() => { loadTargets(); }, []);

  const handleAdd = async () => {
    try {
      await fetch("/api/tc/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: newTarget.id,
          host: newTarget.host,
          target_type: newTarget.target_type,
          access_type: newTarget.access_type,
          port: parseInt(newTarget.port) || 22,
          mode: newTarget.mode,
          credential_name: newTarget.credential_name || null,
          driver: newTarget.driver || null,
        }),
      });
      setShowAdd(false);
      setNewTarget({ id: "", host: "", target_type: "linux", access_type: "ssh", port: "22", mode: "investigator", credential_name: "", driver: "" });
      await loadTargets();
    } catch { /* */ }
  };

  const handleDelete = async (id: string) => {
    try {
      await fetch(`/api/tc/targets/${id}`, { method: "DELETE" });
      await loadTargets();
    } catch { /* */ }
  };

  const inputStyle: React.CSSProperties = {
    width: "100%", border: "none", borderRadius: "6px", padding: "8px 10px",
    fontSize: "11px", color: "#4a3028", fontFamily: "Inter, sans-serif",
    background: "#e2dbd4", outline: "none",
    boxShadow: "inset 0 2px 4px rgba(60,30,15,0.15), inset 0 1px 2px rgba(60,30,15,0.1)",
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
        <ChromeEmbossedText as="h2" style={{ fontSize: "14px", fontWeight: 800 }}>Infrastructure</ChromeEmbossedText>
        <ChromeButton onClick={() => setShowAdd(!showAdd)}>
          <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "10px" }}>
            <Plus size={12} /> Ajouter une cible
          </span>
        </ChromeButton>
      </div>

      {/* Add form */}
      {showAdd && (
        <ChromeInsetCard className="mb-4">
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "10px" }}>
            Nouvelle cible
          </ChromeEmbossedText>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Nom</ChromeEmbossedText>
              <input style={inputStyle} value={newTarget.id} onChange={e => setNewTarget(p => ({ ...p, id: e.target.value }))} placeholder="srv-prod-01" />
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>IP / Hostname</ChromeEmbossedText>
              <input style={inputStyle} value={newTarget.host} onChange={e => setNewTarget(p => ({ ...p, host: e.target.value }))} placeholder="192.168.1.10" />
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Type</ChromeEmbossedText>
              <select style={inputStyle} value={newTarget.target_type} onChange={e => setNewTarget(p => ({ ...p, target_type: e.target.value }))}>
                <option value="linux">Linux</option>
                <option value="windows">Windows</option>
                <option value="firewall">Firewall</option>
                <option value="network">Réseau</option>
              </select>
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Accès</ChromeEmbossedText>
              <select style={inputStyle} value={newTarget.access_type} onChange={e => setNewTarget(p => ({ ...p, access_type: e.target.value }))}>
                <option value="ssh">SSH</option>
                <option value="winrm">WinRM</option>
                <option value="api">API REST</option>
              </select>
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Port</ChromeEmbossedText>
              <input style={inputStyle} value={newTarget.port} onChange={e => setNewTarget(p => ({ ...p, port: e.target.value }))} />
            </div>
            <div>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Mode</ChromeEmbossedText>
              <select style={inputStyle} value={newTarget.mode} onChange={e => setNewTarget(p => ({ ...p, mode: e.target.value }))}>
                <option value="investigator">Investigateur</option>
                <option value="responder">Répondeur (HITL)</option>
                <option value="autonomous_low">Autonome Low</option>
              </select>
            </div>
          </div>
          {newTarget.target_type === "firewall" && (
            <div style={{ marginTop: "8px" }}>
              <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.5, marginBottom: "2px" }}>Driver firewall</ChromeEmbossedText>
              <select style={inputStyle} value={newTarget.driver} onChange={e => setNewTarget(p => ({ ...p, driver: e.target.value }))}>
                <option value="">Sélectionner...</option>
                <option value="pfsense">pfSense / OPNsense</option>
                <option value="stormshield">Stormshield</option>
                <option value="fortinet">Fortinet</option>
                <option value="sophos">Sophos</option>
              </select>
            </div>
          )}
          <div style={{ display: "flex", gap: "8px", marginTop: "12px" }}>
            <ChromeButton onClick={handleAdd}>
              <span style={{ fontSize: "10px" }}>Ajouter</span>
            </ChromeButton>
            <ChromeButton onClick={() => setShowAdd(false)}>
              <span style={{ fontSize: "10px", opacity: 0.5 }}>Annuler</span>
            </ChromeButton>
          </div>
        </ChromeInsetCard>
      )}

      {/* Targets list */}
      {targets.length === 0 && !showAdd ? (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "24px" }}>
            <Wifi size={20} color="#907060" style={{ margin: "0 auto 8px" }} />
            <ChromeEmbossedText as="div" style={{ fontSize: "12px", fontWeight: 700 }}>Aucune cible configurée</ChromeEmbossedText>
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, marginTop: "4px" }}>
              Ajoutez vos serveurs et firewalls pour que ThreatClaw puisse les surveiller et agir dessus.
            </ChromeEmbossedText>
          </div>
        </ChromeInsetCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {targets.map(t => {
            const Icon = TYPE_ICONS[t.target_type] || Server;
            return (
              <ChromeInsetCard key={t.id}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <Icon size={16} color="#5a6a8a" />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <ChromeEmbossedText as="span" style={{ fontSize: "12px", fontWeight: 700 }}>{t.id}</ChromeEmbossedText>
                      <ChromeEmbossedText as="span" style={{ fontSize: "8px", opacity: 0.4, fontFamily: "monospace" }}>{t.host}:{t.port}</ChromeEmbossedText>
                    </div>
                    <ChromeEmbossedText as="div" style={{ fontSize: "8px", opacity: 0.45, marginTop: "2px" }}>
                      {TYPE_LABELS[t.target_type] || t.target_type} · {t.access_type.toUpperCase()} · Mode: {t.mode}
                      {t.driver ? ` · ${t.driver}` : ""}
                      {t.allowed_actions.length > 0 ? ` · ${t.allowed_actions.length} actions` : " · lecture seule"}
                    </ChromeEmbossedText>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    {t.credential_name ? (
                      <CheckCircle2 size={12} color="#5a7a4a" />
                    ) : (
                      <AlertTriangle size={12} color="#906020" />
                    )}
                    <ChromeButton onClick={() => handleDelete(t.id)}>
                      <Trash2 size={10} />
                    </ChromeButton>
                  </div>
                </div>
              </ChromeInsetCard>
            );
          })}
        </div>
      )}
    </div>
  );
}
