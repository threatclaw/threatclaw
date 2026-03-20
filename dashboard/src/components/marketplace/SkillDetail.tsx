"use client";

import React from "react";
import { X, Star, Download, CheckCircle2, Shield, BadgeCheck, Users, Lock } from "lucide-react";
import type { Skill } from "@/lib/skills-data";

const trustConfig = {
  official: { label: "Officiel", icon: Shield, color: "var(--accent-ok)" },
  verified: { label: "Vérifié", icon: BadgeCheck, color: "var(--accent-info)" },
  community: { label: "Communauté", icon: Users, color: "var(--text-secondary)" },
};

interface Props {
  skill: Skill;
  installed: boolean;
  onClose: () => void;
  onInstall: () => void;
}

export default function SkillDetail({ skill, installed, onClose, onInstall }: Props) {
  const trust = trustConfig[skill.trust];
  const TrustIcon = trust.icon;

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 100, background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)", display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onClose}>
      <div
        className="pit scrollbar-thin"
        style={{ maxWidth: "440px", width: "calc(100% - 32px)", maxHeight: "85vh", overflowY: "auto", padding: "20px", position: "relative" }}
        onClick={(e) => e.stopPropagation()}
      >
        <button onClick={onClose} className="btn-raised" style={{ position: "absolute", right: "12px", top: "12px", padding: "4px" }}>
          <X size={12} color="var(--text-secondary)" />
        </button>

        {/* Header */}
        <div style={{ marginBottom: "16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "16px", fontWeight: 800, color: "var(--text-primary)" }}>{skill.name}</span>
            <span style={{ fontSize: "9px", fontFamily: "monospace", color: "var(--text-muted)", background: "var(--bg-pit)", boxShadow: "var(--shadow-pit-xs)", padding: "2px 6px", borderRadius: "4px" }}>
              v{skill.version}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", marginTop: "4px" }}>
            <span style={{ display: "flex", alignItems: "center", gap: "3px", fontSize: "9px", fontWeight: 600, color: trust.color }}>
              <TrustIcon size={12} /> {trust.label}
            </span>
            <span style={{ fontSize: "9px", color: "var(--text-muted)" }}>par {skill.author}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "6px", fontSize: "9px", color: "var(--text-muted)" }}>
            <span style={{ display: "flex", alignItems: "center", gap: "3px" }}><Star size={11} color="var(--accent-warning)" /> {skill.stars}</span>
            <span style={{ display: "flex", alignItems: "center", gap: "3px" }}><Download size={11} /> {skill.downloads.toLocaleString()}</span>
          </div>
        </div>

        {/* Description */}
        <div style={{ marginBottom: "14px" }}>
          <div className="label-caps" style={{ marginBottom: "4px" }}>Description</div>
          <p style={{ fontSize: "11px", lineHeight: 1.5, color: "var(--text-primary)", margin: 0 }}>{skill.longDescription}</p>
        </div>

        {/* Tags */}
        <div style={{ marginBottom: "14px" }}>
          <div className="label-caps" style={{ marginBottom: "4px" }}>Tags</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
            {skill.tags.map((tag) => (
              <span key={tag} style={{ fontSize: "9px", fontWeight: 600, color: "var(--text-secondary)", background: "var(--bg-pit)", boxShadow: "var(--shadow-pit-xs)", padding: "3px 8px", borderRadius: "6px" }}>
                {tag}
              </span>
            ))}
          </div>
        </div>

        {/* Permissions */}
        <div style={{ marginBottom: "14px" }}>
          <div className="label-caps" style={{ marginBottom: "4px" }}>Permissions requises</div>
          <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
            {skill.permissions.map((perm) => (
              <div key={perm} style={{ display: "flex", alignItems: "center", gap: "6px", fontSize: "10px" }}>
                <Lock size={10} color="var(--accent-warning)" />
                <span style={{ fontFamily: "monospace", color: "var(--text-primary)" }}>{perm}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Changelog */}
        <div style={{ marginBottom: "16px" }}>
          <div className="label-caps" style={{ marginBottom: "4px" }}>Versions</div>
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            {skill.changelog.map((entry, i) => (
              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "6px", fontSize: "9px" }}>
                <div style={{ width: "5px", height: "5px", borderRadius: "50%", background: i === 0 ? "var(--accent-danger)" : "var(--text-muted)", marginTop: "4px", flexShrink: 0 }} />
                <span style={{ color: "var(--text-secondary)" }}>{entry}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Action */}
        <button
          onClick={onInstall}
          className="btn-raised-lg"
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
            color: installed ? "var(--accent-danger)" : "var(--accent-ok)",
          }}
        >
          {installed ? <><X size={14} /> Désinstaller</> : <><CheckCircle2 size={14} /> Installer ce skill</>}
        </button>
      </div>
    </div>
  );
}
