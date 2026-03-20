"use client";

import React from "react";
import { Star, Download, CheckCircle2, Shield, BadgeCheck, Users } from "lucide-react";
import type { Skill } from "@/lib/skills-data";

const trustConfig = {
  official: { label: "Officiel", icon: Shield, color: "var(--accent-ok)" },
  verified: { label: "Vérifié", icon: BadgeCheck, color: "var(--accent-info)" },
  community: { label: "Communauté", icon: Users, color: "var(--text-secondary)" },
};

interface Props {
  skill: Skill;
  installed: boolean;
  onSelect: () => void;
  onInstall: () => void;
}

export default function SkillCard({ skill, installed, onSelect, onInstall }: Props) {
  const trust = trustConfig[skill.trust];
  const TrustIcon = trust.icon;

  return (
    <div className="pit" onClick={onSelect} style={{ cursor: "pointer" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <span style={{ fontSize: "12px", fontWeight: 800, color: "var(--text-primary)" }}>{skill.name}</span>
            <span style={{ fontSize: "8px", fontFamily: "monospace", color: "var(--text-muted)", background: "var(--bg-pit)", boxShadow: "var(--shadow-pit-xs)", padding: "1px 5px", borderRadius: "4px" }}>
              v{skill.version}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "4px", marginTop: "2px" }}>
            <TrustIcon size={10} color={trust.color} />
            <span style={{ fontSize: "8px", fontWeight: 600, color: trust.color }}>{trust.label}</span>
            <span style={{ fontSize: "8px", color: "var(--text-muted)" }}>· {skill.author}</span>
          </div>
        </div>
      </div>

      <p style={{ fontSize: "10px", color: "var(--text-secondary)", lineHeight: 1.4, marginBottom: "8px", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden" }}>
        {skill.description}
      </p>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginBottom: "8px" }}>
        {skill.tags.slice(0, 3).map((tag) => (
          <span key={tag} style={{ fontSize: "8px", fontWeight: 600, color: "var(--text-muted)", background: "var(--bg-pit)", boxShadow: "var(--shadow-pit-xs)", padding: "2px 6px", borderRadius: "4px" }}>
            {tag}
          </span>
        ))}
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "9px", color: "var(--text-muted)" }}>
          <span style={{ display: "flex", alignItems: "center", gap: "2px" }}>
            <Star size={10} color="var(--accent-warning)" /> {skill.stars}
          </span>
          <span style={{ display: "flex", alignItems: "center", gap: "2px" }}>
            <Download size={10} /> {skill.downloads.toLocaleString()}
          </span>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onInstall(); }}
          className="btn-raised"
          style={{
            color: installed ? "var(--accent-ok)" : "var(--accent-danger)",
            display: "flex",
            alignItems: "center",
            gap: "3px",
          }}
        >
          {installed ? <><CheckCircle2 size={10} /> Installé</> : "Installer"}
        </button>
      </div>
    </div>
  );
}
