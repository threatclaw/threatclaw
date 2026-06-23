"use client";
// See ADR-044: HITL remediation configuration tab
import { useState, useEffect, useCallback } from "react";
import { Shield, Plus, Trash2, CheckCircle, XCircle, AlertTriangle } from "lucide-react";

const API = "/api/tc";

interface RemediationConfig {
  protected_assets: string[];
  approvers: ChannelApprover[];
  limits: { max_isolations_per_hour: number; max_approvals_per_hour: number };
  connectors: ConnectorStatus[];
}

interface ChannelApprover {
  channel: string;
  id: string;
  label: string;
}

interface ConnectorStatus {
  name: string;
  type: string;
  configured: boolean;
  url?: string;
}

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface)", border: "1px solid var(--tc-border)",
  borderRadius: 12, padding: "16px 20px", marginBottom: 16,
};
const labelStyle: React.CSSProperties = {
  fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const,
  letterSpacing: "0.05em", color: "var(--tc-text-muted)", marginBottom: 8,
};
const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 12px", borderRadius: 8, fontSize: 13,
  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
  color: "var(--tc-text)", outline: "none",
};
const btnStyle: React.CSSProperties = {
  padding: "6px 14px", borderRadius: 8, fontSize: 11, fontWeight: 600,
  cursor: "pointer", border: "1px solid var(--tc-border)", background: "var(--tc-surface)",
  color: "var(--tc-text)",
};

export default function RemediationTab() {
  const [protectedAssets, setProtectedAssets] = useState<string[]>([]);
  const [approvers, setApprovers] = useState<ChannelApprover[]>([]);
  const [limits, setLimits] = useState({ max_isolations_per_hour: 3, max_approvals_per_hour: 10 });
  const [connectors, setConnectors] = useState<ConnectorStatus[]>([]);
  const [newAsset, setNewAsset] = useState("");
  const [newApprover, setNewApprover] = useState({ channel: "telegram", id: "", label: "" });
  const [saved, setSaved] = useState(false);
  const [configuredChannels, setConfiguredChannels] = useState<string[]>([]);

  const load = useCallback(async () => {
    try {
      // Load protected assets
      const r1 = await fetch(`${API}/settings/_system/tc_protected_assets`);
      if (r1.ok) {
        const d = await r1.json();
        if (Array.isArray(d.value)) setProtectedAssets(d.value);
      }
      // Load approvers
      const r2 = await fetch(`${API}/settings/_system/tc_hitl_approvers_config`);
      if (r2.ok) {
        const d = await r2.json();
        if (Array.isArray(d.value)) setApprovers(d.value);
      }
      // Load limits
      const r3 = await fetch(`${API}/settings/_system/tc_hitl_limits`);
      if (r3.ok) {
        const d = await r3.json();
        if (d.value) setLimits(d.value);
      }
      // Load configured channels
      const r4 = await fetch(`${API}/settings/_system/tc_config_channels`);
      if (r4.ok) {
        const d = await r4.json();
        if (d.value) {
          const channels: string[] = [];
          for (const [k, v] of Object.entries(d.value as Record<string, any>)) {
            if (v && typeof v === "object" && v.enabled !== false) {
              const hasToken = Object.values(v).some((val: any) => typeof val === "string" && val.length > 5);
              if (hasToken) channels.push(k);
            }
          }
          setConfiguredChannels(channels);
        }
      }
      // Load connector status
      const skills = ["skill-pfsense", "skill-opnsense", "skill-active-directory", "skill-glpi"];
      const conns: ConnectorStatus[] = [];
      for (const s of skills) {
        const r = await fetch(`${API}/settings/${s}/config`);
        const name = s.replace("skill-", "");
        if (r.ok) {
          const d = await r.json();
          const url = d.value?.url || d.value?.host || d.value?.api_url || "";
          conns.push({ name, type: "remediation", configured: !!url, url });
        } else {
          conns.push({ name, type: "remediation", configured: false });
        }
      }
      setConnectors(conns);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { load(); }, [load]);

  const save = async () => {
    await fetch(`${API}/config`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tc_protected_assets: protectedAssets,
        tc_hitl_approvers_config: approvers,
        tc_hitl_approvers: approvers.filter(a => a.channel === "telegram").map(a => parseInt(a.id) || 0),
        tc_hitl_limits: limits,
      }),
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const addAsset = () => {
    if (newAsset.trim() && !protectedAssets.includes(newAsset.trim())) {
      setProtectedAssets([...protectedAssets, newAsset.trim()]);
      setNewAsset("");
    }
  };

  const removeAsset = (i: number) => {
    setProtectedAssets(protectedAssets.filter((_, idx) => idx !== i));
  };

  const addApprover = () => {
    if (newApprover.id.trim()) {
      setApprovers([...approvers, { ...newApprover, id: newApprover.id.trim(), label: newApprover.label.trim() || newApprover.id.trim() }]);
      setNewApprover({ channel: newApprover.channel, id: "", label: "" });
    }
  };

  const removeApprover = (i: number) => {
    setApprovers(approvers.filter((_, idx) => idx !== i));
  };

  const channelLabels: Record<string, string> = {
    telegram: "Telegram", slack: "Slack", discord: "Discord",
    mattermost: "Mattermost", signal: "Signal", whatsapp: "WhatsApp", olvid: "Olvid",
  };

  const channelIdHelp: Record<string, string> = {
    telegram: "ID numerique (envoyez /start a @userinfobot)",
    slack: "User ID (ex: U01234ABC)",
    discord: "User ID numerique (mode developpeur)",
    mattermost: "Username",
    signal: "Numero de telephone",
    whatsapp: "Numero de telephone",
    olvid: "Discussion ID",
  };

  return (
    <div>
      {/* Protected Assets */}
      <div style={cardStyle}>
        <div style={labelStyle}>Assets proteges (jamais isoles/bloques)</div>
        <div style={{ fontSize: 11, color: "var(--tc-text-muted)", marginBottom: 12 }}>
          Ces IPs/hostnames ne pourront jamais etre isoles ou bloques, meme avec approbation HITL.
          Le serveur ThreatClaw est toujours protege automatiquement.
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", borderRadius: 8, background: "rgba(48,160,80,0.1)", border: "1px solid rgba(48,160,80,0.2)", marginBottom: 12, fontSize: 11, color: "#30a050" }}>
          <Shield size={12} /> Le serveur ThreatClaw + sa gateway sont proteges automatiquement (non modifiable)
        </div>

        {protectedAssets.map((asset, i) => (
          <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", borderRadius: 6, background: "var(--tc-input)", marginBottom: 4 }}>
            <span style={{ fontSize: 13, fontFamily: "monospace" }}>{asset}</span>
            <button onClick={() => removeAsset(i)} style={{ ...btnStyle, padding: "2px 6px", color: "#d03020", border: "none", background: "transparent" }}><Trash2 size={12} /></button>
          </div>
        ))}

        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <input style={inputStyle} placeholder="IP ou hostname (ex: 192.168.1.1, srv-dc-01)" value={newAsset} onChange={e => setNewAsset(e.target.value)} onKeyDown={e => e.key === "Enter" && addAsset()} />
          <button onClick={addAsset} style={{ ...btnStyle, background: "rgba(48,160,80,0.15)", color: "#30a050", border: "1px solid rgba(48,160,80,0.3)" }}><Plus size={12} /></button>
        </div>

        <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 8 }}>
          <AlertTriangle size={10} style={{ display: "inline", marginRight: 4 }} />
          Changements pris en compte au prochain redemarrage
        </div>
      </div>

      {/* Approvers */}
      <div style={cardStyle}>
        <div style={labelStyle}>Approvers HITL (qui peut approuver les remediations)</div>
        <div style={{ fontSize: 11, color: "var(--tc-text-muted)", marginBottom: 12 }}>
          Seules ces personnes peuvent approuver des actions de remediation sur chaque canal.
          Si la liste est vide pour un canal, tout membre du chat autorise peut approuver.
        </div>

        {approvers.map((ap, i) => (
          <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 10px", borderRadius: 6, background: "var(--tc-input)", marginBottom: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 4, background: "rgba(64,144,255,0.15)", color: "#4090ff", fontWeight: 600 }}>{channelLabels[ap.channel] || ap.channel}</span>
              <span style={{ fontSize: 13, fontFamily: "monospace" }}>{ap.id}</span>
              {ap.label && ap.label !== ap.id && <span style={{ fontSize: 11, color: "var(--tc-text-muted)" }}>({ap.label})</span>}
            </div>
            <button onClick={() => removeApprover(i)} style={{ ...btnStyle, padding: "2px 6px", color: "#d03020", border: "none", background: "transparent" }}><Trash2 size={12} /></button>
          </div>
        ))}

        <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
          <select
            value={newApprover.channel}
            onChange={e => setNewApprover({ ...newApprover, channel: e.target.value })}
            style={{ ...inputStyle, width: 130, flex: "none" }}
          >
            {(configuredChannels.length > 0 ? configuredChannels : ["telegram"]).map(ch => (
              <option key={ch} value={ch}>{channelLabels[ch] || ch}</option>
            ))}
          </select>
          <input style={{ ...inputStyle, flex: 1, minWidth: 120 }} placeholder="ID" value={newApprover.id} onChange={e => setNewApprover({ ...newApprover, id: e.target.value })} />
          <input style={{ ...inputStyle, flex: 1, minWidth: 100 }} placeholder="Nom (optionnel)" value={newApprover.label} onChange={e => setNewApprover({ ...newApprover, label: e.target.value })} />
          <button onClick={addApprover} style={{ ...btnStyle, background: "rgba(64,144,255,0.15)", color: "#4090ff", border: "1px solid rgba(64,144,255,0.3)" }}><Plus size={12} /></button>
        </div>
        {newApprover.channel && (
          <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 4 }}>
            {channelIdHelp[newApprover.channel] || "Identifiant unique sur ce canal"}
          </div>
        )}
      </div>

      {/* Rate Limits */}
      <div style={cardStyle}>
        <div style={labelStyle}>Limites de securite</div>
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 12, marginBottom: 4 }}>Isolations max / heure</div>
            <input type="number" min={1} max={10} value={limits.max_isolations_per_hour} onChange={e => setLimits({ ...limits, max_isolations_per_hour: parseInt(e.target.value) || 3 })} style={{ ...inputStyle, width: 80 }} />
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <div style={{ fontSize: 12, marginBottom: 4 }}>Approbations HITL max / heure</div>
            <input type="number" min={1} max={50} value={limits.max_approvals_per_hour} onChange={e => setLimits({ ...limits, max_approvals_per_hour: parseInt(e.target.value) || 10 })} style={{ ...inputStyle, width: 80 }} />
          </div>
        </div>
        <div style={{ fontSize: 10, color: "var(--tc-text-muted)", marginTop: 8 }}>
          <AlertTriangle size={10} style={{ display: "inline", marginRight: 4 }} />
          Changements pris en compte au prochain redemarrage (valeurs verrouillees en memoire au boot)
        </div>
      </div>

      {/* Connector Status */}
      <div style={cardStyle}>
        <div style={labelStyle}>Connecteurs de remediation</div>
        <div style={{ display: "grid", gap: 8 }}>
          {connectors.map(c => (
            <div key={c.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 12px", borderRadius: 8, background: "var(--tc-input)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {c.configured ? <CheckCircle size={14} color="#30a050" /> : <XCircle size={14} color="#888" />}
                <span style={{ fontSize: 13, fontWeight: 600, textTransform: "capitalize" }}>{c.name.replace("-", " ")}</span>
                {c.url && <span style={{ fontSize: 11, color: "var(--tc-text-muted)", fontFamily: "monospace" }}>{c.url}</span>}
              </div>
              <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: c.configured ? "rgba(48,160,80,0.15)" : "rgba(136,136,136,0.15)", color: c.configured ? "#30a050" : "#888", fontWeight: 600 }}>
                {c.configured ? "Configure" : "Non configure"}
              </span>
            </div>
          ))}
        </div>
        <div style={{ fontSize: 11, color: "var(--tc-text-muted)", marginTop: 8 }}>
          Configurez les connecteurs dans la page Skills (pfSense, Active Directory, GLPI)
        </div>
      </div>

      {/* Save button */}
      <button onClick={save} style={{
        ...btnStyle, width: "100%", padding: "12px", fontSize: 13,
        background: saved ? "rgba(48,160,80,0.15)" : "rgba(208,48,32,0.15)",
        color: saved ? "#30a050" : "#d03020",
        border: `1px solid ${saved ? "rgba(48,160,80,0.3)" : "rgba(208,48,32,0.3)"}`,
      }}>
        {saved ? "Sauvegarde !" : "Sauvegarder la configuration remediation"}
      </button>
    </div>
  );
}
