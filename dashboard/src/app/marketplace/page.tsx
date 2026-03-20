"use client";

import React, { useState, useMemo } from "react";
import { Search, Plus } from "lucide-react";
import { skills, type Skill } from "@/lib/skills-data";
import SkillCard from "@/components/marketplace/SkillCard";
import SkillDetail from "@/components/marketplace/SkillDetail";
import Header from "@/components/Header";

type TrustFilter = "all" | "installed" | "official" | "verified" | "community";

const CATEGORIES = [
  "Toutes",
  "Scanning & Détection",
  "Conformité & Audit",
  "Monitoring & SOC",
  "Sensibilisation",
  "Infrastructure",
  "Rapports",
];

const SKILL_CATEGORIES: Record<string, string> = {
  "skill-vuln-scan": "Scanning & Détection",
  "skill-secrets-audit": "Scanning & Détection",
  "skill-email-audit": "Conformité & Audit",
  "skill-darkweb-monitor": "Monitoring & SOC",
  "skill-phishing-sim": "Sensibilisation",
  "skill-soc-monitor": "Monitoring & SOC",
  "skill-cloud-posture": "Infrastructure",
  "skill-report-gen": "Rapports",
  "skill-compliance-nis2": "Conformité & Audit",
  "skill-compliance-iso27001": "Conformité & Audit",
  "skill-ad-audit": "Infrastructure",
  "skill-wifi-audit": "Scanning & Détection",
  "skill-backup-check": "Infrastructure",
  "skill-cert-monitor": "Monitoring & SOC",
  "skill-ransomware-sim": "Sensibilisation",
  "skill-asset-discovery": "Scanning & Détection",
  "skill-password-audit": "Scanning & Détection",
  "skill-firewall-audit": "Infrastructure",
};

export default function MarketplacePage() {
  const [search, setSearch] = useState("");
  const [trustFilter, setTrustFilter] = useState<TrustFilter>("all");
  const [category, setCategory] = useState("Toutes");
  const [selected, setSelected] = useState<Skill | null>(null);
  const [installedIds, setInstalledIds] = useState<Set<string>>(
    new Set(skills.filter((s) => s.installed).map((s) => s.id))
  );

  const filtered = useMemo(() => {
    let result = skills;

    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (s) => s.name.toLowerCase().includes(q) || s.description.toLowerCase().includes(q) || s.tags.some((t) => t.toLowerCase().includes(q))
      );
    }

    if (category !== "Toutes") {
      result = result.filter((s) => SKILL_CATEGORIES[s.id] === category);
    }

    switch (trustFilter) {
      case "installed": result = result.filter((s) => installedIds.has(s.id)); break;
      case "official": result = result.filter((s) => s.trust === "official"); break;
      case "verified": result = result.filter((s) => s.trust === "verified"); break;
      case "community": result = result.filter((s) => s.trust === "community"); break;
    }

    return result;
  }, [search, trustFilter, category, installedIds]);

  const handleInstall = (id: string) => {
    setInstalledIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const trustFilters: { id: TrustFilter; label: string }[] = [
    { id: "all", label: "Tous" },
    { id: "installed", label: "Installés" },
    { id: "official", label: "Officiels" },
    { id: "verified", label: "Vérifiés" },
    { id: "community", label: "Communauté" },
  ];

  return (
    <div>
      <Header subtitle="Marketplace des Skills" />

      {/* Search + Propose */}
      <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
        <div style={{ flex: 1, position: "relative" }}>
          <Search size={14} color="var(--text-muted)" style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)" }} />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-pit"
            placeholder="Rechercher un skill..."
            style={{ paddingLeft: "34px" }}
          />
        </div>
        <button className="btn-raised" style={{ display: "flex", alignItems: "center", gap: "4px", padding: "8px 12px", whiteSpace: "nowrap" }}>
          <Plus size={12} />
          Proposer un skill
        </button>
      </div>

      {/* Categories */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "8px", overflowX: "auto", paddingBottom: "4px" }} className="scrollbar-thin">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategory(cat)}
            className={category === cat ? "btn-raised" : ""}
            style={{
              padding: "4px 10px",
              fontSize: "9px",
              fontWeight: 700,
              letterSpacing: "0.04em",
              whiteSpace: "nowrap",
              border: "none",
              borderRadius: "8px",
              cursor: "pointer",
              background: category === cat ? "var(--bg-base)" : "transparent",
              color: category === cat ? "var(--accent-danger)" : "var(--text-muted)",
              boxShadow: category === cat ? "var(--shadow-bump)" : "none",
            }}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Trust filters */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px" }}>
        {trustFilters.map((f) => (
          <button
            key={f.id}
            onClick={() => setTrustFilter(f.id)}
            style={{
              padding: "3px 8px",
              fontSize: "8px",
              fontWeight: 700,
              letterSpacing: "0.06em",
              textTransform: "uppercase",
              border: "none",
              borderRadius: "6px",
              cursor: "pointer",
              background: trustFilter === f.id ? "var(--bg-pit)" : "transparent",
              boxShadow: trustFilter === f.id ? "var(--shadow-pit-xs)" : "none",
              color: trustFilter === f.id ? "var(--accent-danger)" : "var(--text-muted)",
            }}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: "10px" }}>
        {filtered.map((skill) => (
          <SkillCard
            key={skill.id}
            skill={skill}
            installed={installedIds.has(skill.id)}
            onSelect={() => setSelected(skill)}
            onInstall={() => handleInstall(skill.id)}
          />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="pit" style={{ textAlign: "center", marginTop: "24px" }}>
          <p style={{ fontSize: "11px", color: "var(--text-muted)" }}>Aucun skill trouvé.</p>
        </div>
      )}

      {selected && (
        <SkillDetail
          skill={selected}
          installed={installedIds.has(selected.id)}
          onClose={() => setSelected(null)}
          onInstall={() => handleInstall(selected.id)}
        />
      )}
    </div>
  );
}
