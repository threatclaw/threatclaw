"use client";

import React, { useState, useEffect } from "react";
import { ChromeInsetCard, ChromeEmbossedText } from "@/components/chrome/ChromeCard";
import { ChromeButton } from "@/components/chrome/ChromeButton";
import { CheckCircle2, Download, Search, AlertTriangle, ExternalLink } from "lucide-react";

interface Skill {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  trust: string;
  category: string;
  runtime: string;
  installed: boolean;
  api_key_required?: boolean;
  requires_network?: boolean;
  secrets?: string[];
}

const CATEGORY_LABELS: Record<string, string> = {
  scanning: "Scanning", compliance: "Conformité", monitoring: "Monitoring",
  rapports: "Rapports", infrastructure: "Infrastructure",
};

export default function SkillsPage() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("/api/tc/skills/catalog")
      .then(r => r.json())
      .then(d => { setSkills(d.skills || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const filtered = search
    ? skills.filter(s => s.name?.toLowerCase().includes(search.toLowerCase()) || s.description?.toLowerCase().includes(search.toLowerCase()))
    : skills;

  const installed = filtered.filter(s => s.installed);
  const available = filtered.filter(s => !s.installed);

  if (loading) return (
    <ChromeInsetCard>
      <div style={{ textAlign: "center", padding: "24px" }}>
        <ChromeEmbossedText as="div" style={{ fontSize: "11px" }}>Chargement des skills...</ChromeEmbossedText>
      </div>
    </ChromeInsetCard>
  );

  return (
    <div>
      {/* Search */}
      <ChromeInsetCard className="mb-4">
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <Search size={14} color="#907060" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Rechercher un skill..."
            style={{ flex: 1, border: "none", background: "transparent", outline: "none", fontSize: "11px", color: "#4a3028", fontFamily: "Inter, sans-serif" }} />
          <ChromeEmbossedText as="span" style={{ fontSize: "9px", opacity: 0.4 }}>{skills.length} skills</ChromeEmbossedText>
        </div>
      </ChromeInsetCard>

      {/* Installed */}
      {installed.length > 0 && (
        <>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
            Installés ({installed.length})
          </ChromeEmbossedText>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "20px" }}>
            {installed.map(skill => <SkillRow key={skill.id} skill={skill} />)}
          </div>
        </>
      )}

      {/* Available */}
      {available.length > 0 && (
        <>
          <ChromeEmbossedText as="div" style={{ fontSize: "10px", fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px", opacity: 0.5 }}>
            Disponibles ({available.length})
          </ChromeEmbossedText>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {available.map(skill => <SkillRow key={skill.id} skill={skill} />)}
          </div>
        </>
      )}

      {skills.length === 0 && (
        <ChromeInsetCard>
          <div style={{ textAlign: "center", padding: "24px" }}>
            <ChromeEmbossedText as="div" style={{ fontSize: "12px", fontWeight: 700 }}>Aucun skill trouvé</ChromeEmbossedText>
            <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, marginTop: "4px" }}>
              Vérifiez que le core ThreatClaw est démarré.
            </ChromeEmbossedText>
          </div>
        </ChromeInsetCard>
      )}
    </div>
  );
}

function SkillRow({ skill }: { skill: Skill }) {
  return (
    <ChromeInsetCard>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "3px" }}>
            <ChromeEmbossedText as="span" style={{ fontSize: "12px", fontWeight: 700 }}>
              {skill.name || skill.id}
            </ChromeEmbossedText>
            <ChromeEmbossedText as="span" style={{ fontSize: "8px", opacity: 0.35, fontFamily: "monospace" }}>
              v{skill.version || "1.0.0"}
            </ChromeEmbossedText>
            {skill.installed && <CheckCircle2 size={12} color="#5a7a4a" />}
            {skill.runtime === "wasm" && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", fontWeight: 700, color: "#5a6a8a", background: "rgba(90,106,138,0.1)", padding: "1px 4px", borderRadius: "3px" }}>
                WASM
              </ChromeEmbossedText>
            )}
          </div>
          <ChromeEmbossedText as="div" style={{ fontSize: "9px", opacity: 0.5, lineHeight: 1.3 }}>
            {skill.description}
          </ChromeEmbossedText>
          <div style={{ display: "flex", gap: "6px", marginTop: "4px", alignItems: "center" }}>
            {skill.category && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", fontWeight: 700, textTransform: "uppercase", opacity: 0.35, background: "rgba(0,0,0,0.04)", padding: "1px 4px", borderRadius: "3px" }}>
                {CATEGORY_LABELS[skill.category] || skill.category}
              </ChromeEmbossedText>
            )}
            {skill.api_key_required && (
              <ChromeEmbossedText as="span" style={{ fontSize: "7px", color: "#906020", display: "flex", alignItems: "center", gap: "2px" }}>
                <AlertTriangle size={8} /> Clé API requise
              </ChromeEmbossedText>
            )}
            <ChromeEmbossedText as="span" style={{ fontSize: "7px", opacity: 0.3 }}>
              {skill.trust === "official" ? "Officiel" : skill.trust === "verified" ? "Vérifié" : "Communauté"}
            </ChromeEmbossedText>
          </div>
        </div>
        <div>
          {skill.installed ? (
            <ChromeButton onClick={() => window.location.href = "/setup"}>
              <span style={{ fontSize: "9px" }}>Configurer</span>
            </ChromeButton>
          ) : (
            <ChromeButton onClick={() => alert(`Installation de ${skill.id} — disponible prochainement via "threatclaw skill install ${skill.id}"`)}>
              <span style={{ display: "flex", alignItems: "center", gap: "4px", fontSize: "9px" }}>
                <Download size={10} /> Installer
              </span>
            </ChromeButton>
          )}
        </div>
      </div>
    </ChromeInsetCard>
  );
}
