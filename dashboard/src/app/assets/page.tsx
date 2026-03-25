"use client";

import React, { useState, useEffect, useCallback } from "react";
import { useLocale } from "@/lib/useLocale";
import {
  Server, Monitor, Smartphone, Globe, Network, Printer, Cpu, Factory, Cloud, HelpCircle,
  Plus, Search, Settings, Trash2, X, RefreshCw, Loader2, Shield, ChevronRight, ChevronLeft,
  AlertTriangle, Eye, CheckCircle2, Wifi,
} from "lucide-react";
import { NeuCard } from "@/components/chrome/NeuCard";

// ── Types ──

interface Asset {
  id: string; name: string; category: string; subcategory: string | null;
  role: string | null; criticality: string; ip_addresses: string[];
  mac_address: string | null; hostname: string | null; fqdn: string | null;
  url: string | null; os: string | null; os_confidence: number;
  mac_vendor: string | null; services: any; source: string; status: string;
  last_seen: string; first_seen: string; owner: string | null;
  location: string | null; tags: string[]; notes: string | null;
  classification_method: string; classification_confidence: number;
}

interface Category {
  id: string; label: string; label_en: string | null; icon: string;
  color: string; subcategories: string[]; is_builtin: boolean;
}

// ── Constants ──

const ICON_MAP: Record<string, React.ElementType> = {
  server: Server, monitor: Monitor, smartphone: Smartphone, globe: Globe,
  network: Network, printer: Printer, cpu: Cpu, factory: Factory,
  cloud: Cloud, "help-circle": HelpCircle,
};

const CRIT_COLORS: Record<string, { color: string; label: string }> = {
  critical: { color: "#e04040", label: "Critique" },
  high: { color: "#d07020", label: "Haut" },
  medium: { color: "#d09020", label: "Moyen" },
  low: { color: "#30a050", label: "Bas" },
};

const CAT_DESCRIPTIONS: Record<string, string> = {
  server: "Serveurs physiques ou virtuels (web, base de données, mail, AD...)",
  workstation: "Postes de travail fixes, laptops, tablettes",
  mobile: "Smartphones et tablettes",
  website: "Sites web, applications SaaS, APIs",
  network: "Firewalls, switches, routeurs, bornes WiFi",
  printer: "Imprimantes, scanners, copieurs réseau",
  iot: "Caméras, badges, capteurs, objets connectés",
  ot: "Automates industriels, SCADA, HMI",
  cloud: "VMs cloud, containers, fonctions serverless",
  unknown: "Devices détectés automatiquement, en attente de classification",
};

// ── Styles ──

const cardStyle: React.CSSProperties = {
  background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)", padding: "20px",
};

const inputStyle: React.CSSProperties = {
  width: "100%", padding: "8px 10px", fontSize: "11px", fontFamily: "inherit",
  background: "var(--tc-input)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-sm)", color: "var(--tc-text)", outline: "none",
};

const labelStyle: React.CSSProperties = {
  fontSize: "9px", fontWeight: 700, color: "var(--tc-text-muted)",
  textTransform: "uppercase" as const, letterSpacing: "0.05em", marginBottom: "3px", display: "block",
};

const btnPrimary: React.CSSProperties = {
  background: "var(--tc-red)", color: "#fff", border: "none", borderRadius: "var(--tc-radius-md)",
  padding: "10px 20px", fontSize: "12px", fontWeight: 700, cursor: "pointer", fontFamily: "inherit",
  display: "inline-flex", alignItems: "center", gap: "6px",
};

const btnSecondary: React.CSSProperties = {
  background: "var(--tc-input)", color: "var(--tc-text-sec)", border: "1px solid var(--tc-border)",
  borderRadius: "var(--tc-radius-md)", padding: "8px 14px", fontSize: "11px", fontWeight: 600,
  cursor: "pointer", fontFamily: "inherit", display: "inline-flex", alignItems: "center", gap: "4px",
};

// ── Component ──

export default function AssetsPage() {
  const locale = useLocale();
  const [assets, setAssets] = useState<Asset[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("all");
  const [search, setSearch] = useState("");

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [modalStep, setModalStep] = useState(0); // 0=pick category, 1=fill form
  const [editAsset, setEditAsset] = useState<Asset | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Form state
  const [form, setForm] = useState({
    category: "", subcategory: "", name: "", role: "", criticality: "medium",
    ip: "", hostname: "", fqdn: "", os: "", url: "", mac: "",
    owner: "", location: "", notes: "",
  });

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [aRes, cRes, countRes] = await Promise.all([
        fetch(`/api/tc/assets?limit=500${activeTab !== "all" ? `&category=${activeTab}` : ""}`),
        fetch("/api/tc/assets/categories"),
        fetch("/api/tc/assets/counts"),
      ]);
      const aData = await aRes.json();
      const cData = await cRes.json();
      const countData = await countRes.json();
      setAssets(aData.assets || []);
      setCategories(cData.categories || []);
      const m: Record<string, number> = {};
      for (const c of countData.counts || []) m[c.category] = c.count;
      setCounts(m);
    } catch { /* */ }
    setLoading(false);
  }, [activeTab]);

  useEffect(() => { loadData(); }, [loadData]);

  // ── Modal handlers ──

  const openAdd = () => {
    setEditAsset(null);
    setForm({ category: "", subcategory: "", name: "", role: "", criticality: "medium", ip: "", hostname: "", fqdn: "", os: "", url: "", mac: "", owner: "", location: "", notes: "" });
    setModalStep(0);
    setShowModal(true);
  };

  const openEdit = (a: Asset) => {
    setEditAsset(a);
    setForm({
      category: a.category, subcategory: a.subcategory || "", name: a.name,
      role: a.role || "", criticality: a.criticality,
      ip: a.ip_addresses.join(", "), hostname: a.hostname || "",
      fqdn: a.fqdn || "", os: a.os || "", url: a.url || "",
      mac: a.mac_address || "", owner: a.owner || "",
      location: a.location || "", notes: a.notes || "",
    });
    setModalStep(1);
    setShowModal(true);
  };

  const selectCategory = (catId: string) => {
    setForm(f => ({ ...f, category: catId }));
    setModalStep(1);
  };

  const handleSave = async () => {
    const body: Record<string, unknown> = {
      name: form.name, category: form.category,
      subcategory: form.subcategory || undefined,
      role: form.role || undefined, criticality: form.criticality,
      hostname: form.hostname || undefined, fqdn: form.fqdn || undefined,
      os: form.os || undefined, url: form.url || undefined,
      mac_address: form.mac || undefined,
      owner: form.owner || undefined, location: form.location || undefined,
      notes: form.notes || undefined,
    };
    if (form.ip) body.ip_addresses = form.ip.split(",").map(s => s.trim()).filter(Boolean);
    if (editAsset) body.id = editAsset.id;
    await fetch("/api/tc/assets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setShowModal(false);
    loadData();
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Supprimer cet asset ?")) return;
    await fetch(`/api/tc/assets/${id}`, { method: "DELETE" });
    loadData();
  };

  // ── Filtered assets ──

  const filtered = assets.filter(a => {
    if (!search) return true;
    const s = search.toLowerCase();
    return a.name.toLowerCase().includes(s) || a.ip_addresses.some(ip => ip.includes(s)) ||
      (a.hostname || "").toLowerCase().includes(s) || (a.role || "").toLowerCase().includes(s) ||
      (a.os || "").toLowerCase().includes(s);
  });

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const activeCat = categories.find(c => c.id === form.category);

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
        <div>
          <h1 style={{ fontSize: "24px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>Assets</h1>
          <p style={{ fontSize: "13px", color: "var(--tc-text-muted)", margin: "4px 0 0" }}>
            {total} asset{total !== 1 ? "s" : ""} dans votre infrastructure
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button onClick={openAdd} style={btnPrimary}><Plus size={13} /> Ajouter un asset</button>
          <button onClick={loadData} style={btnSecondary}><RefreshCw size={12} /></button>
        </div>
      </div>

      {/* Category tabs */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px", flexWrap: "wrap" }}>
        <button onClick={() => setActiveTab("all")} style={{
          padding: "6px 12px", fontSize: "10px", fontWeight: 700, borderRadius: "var(--tc-radius-sm)",
          cursor: "pointer", fontFamily: "inherit", textTransform: "uppercase", letterSpacing: "0.05em",
          background: activeTab === "all" ? "var(--tc-red)" : "var(--tc-input)",
          color: activeTab === "all" ? "#fff" : "var(--tc-text-muted)",
          border: activeTab === "all" ? "none" : "1px solid var(--tc-border)",
        }}>
          Tous ({total})
        </button>
        {categories.filter(c => (counts[c.id] || 0) > 0 || c.id === "unknown").map(cat => {
          const Icon = ICON_MAP[cat.icon] || HelpCircle;
          const count = counts[cat.id] || 0;
          return (
            <button key={cat.id} onClick={() => setActiveTab(cat.id)} style={{
              padding: "6px 12px", fontSize: "10px", fontWeight: 600, borderRadius: "var(--tc-radius-sm)",
              cursor: "pointer", fontFamily: "inherit", display: "flex", alignItems: "center", gap: "4px",
              background: activeTab === cat.id ? cat.color : "var(--tc-input)",
              color: activeTab === cat.id ? "#fff" : "var(--tc-text-muted)",
              border: activeTab === cat.id ? "none" : "1px solid var(--tc-border)",
            }}>
              <Icon size={11} /> {locale === "en" ? (cat.label_en || cat.label) : cat.label} ({count})
            </button>
          );
        })}
      </div>

      {/* Search */}
      <div style={{ marginBottom: "16px", position: "relative" }}>
        <Search size={13} style={{ position: "absolute", left: "10px", top: "9px", color: "var(--tc-text-muted)" }} />
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Rechercher par nom, IP, hostname, rôle, OS..."
          style={{ ...inputStyle, paddingLeft: "30px" }} />
      </div>

      {/* Assets list */}
      {loading ? (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)" }}>
          <Loader2 size={20} className="animate-spin" style={{ margin: "0 auto 8px" }} /> Chargement...
        </div>
      ) : filtered.length === 0 ? (
        <NeuCard style={{ textAlign: "center", padding: "40px", color: "var(--tc-text-muted)", fontSize: "12px" }}>
          {search ? "Aucun asset avec ce filtre." : "Aucun asset. Ajoutez vos serveurs, postes, sites web et équipements réseau."}
        </NeuCard>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
          {filtered.map(a => {
            const cat = categories.find(c => c.id === a.category);
            const Icon = ICON_MAP[cat?.icon || "help-circle"] || HelpCircle;
            const crit = CRIT_COLORS[a.criticality] || { color: "var(--tc-text-muted)", label: a.criticality };
            const isExpanded = expandedId === a.id;
            return (
              <div key={a.id}>
                <NeuCard onClick={() => setExpandedId(isExpanded ? null : a.id)} style={{
                  borderRadius: isExpanded ? "var(--tc-radius-md) var(--tc-radius-md) 0 0" : undefined,
                  padding: "12px 14px", cursor: "pointer",
                }}>
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  {/* Icon */}
                  <div style={{ width: "32px", height: "32px", borderRadius: "var(--tc-radius-sm)", display: "flex", alignItems: "center", justifyContent: "center", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: cat?.color || "var(--tc-text-muted)", flexShrink: 0 }}>
                    <Icon size={16} />
                  </div>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
                      <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>{a.name}</span>
                      <span style={{ fontSize: "8px", fontWeight: 700, padding: "1px 5px", borderRadius: "3px", textTransform: "uppercase",
                        background: `${crit.color}15`, color: crit.color, border: `1px solid ${crit.color}30` }}>
                        {crit.label}
                      </span>
                      {a.subcategory && <span style={{ fontSize: "8px", color: "var(--tc-text-muted)", padding: "1px 4px", borderRadius: "3px", background: "var(--tc-input)" }}>{a.subcategory}</span>}
                      {a.source !== "manual" && <span style={{ fontSize: "8px", color: "var(--tc-blue)", padding: "1px 4px", borderRadius: "3px", background: "rgba(48,128,208,0.08)" }}>{a.source}</span>}
                      {a.category === "unknown" && <span style={{ fontSize: "8px", color: "var(--tc-amber)", padding: "1px 4px", borderRadius: "3px", background: "rgba(208,144,32,0.08)" }}>auto-détecté</span>}
                    </div>
                    <div style={{ fontSize: "10px", color: "var(--tc-text-muted)", marginTop: "2px", display: "flex", gap: "12px", flexWrap: "wrap" }}>
                      {a.ip_addresses.length > 0 && <span>{a.ip_addresses.join(", ")}</span>}
                      {a.hostname && <span>{a.hostname}</span>}
                      {a.os && <span>{a.os}</span>}
                      {a.role && <span style={{ fontStyle: "italic" }}>{a.role}</span>}
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: "flex", gap: "4px", flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                    <button onClick={() => openEdit(a)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}><Settings size={13} /></button>
                    <button onClick={() => handleDelete(a.id)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px" }}><Trash2 size={13} /></button>
                  </div>

                  {isExpanded ? <ChevronRight size={12} style={{ color: "var(--tc-text-muted)", transform: "rotate(90deg)", transition: "transform 0.2s" }} /> : <ChevronRight size={12} style={{ color: "var(--tc-text-muted)" }} />}
                </div>
                </NeuCard>

                {/* Expanded details */}
                {isExpanded && (
                  <div style={{
                    background: "var(--tc-neu-inner)", borderRadius: "0 0 var(--tc-radius-md) var(--tc-radius-md)",
                    padding: "14px", marginTop: "-4px",
                    boxShadow: "inset 0 2px 6px rgba(0,0,0,0.2)",
                  }}>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px", fontSize: "10px" }}>
                      <div>
                        <span style={labelStyle}>Catégorie</span>
                        <div style={{ color: "var(--tc-text)" }}>{cat?.label || a.category}{a.subcategory ? ` > ${a.subcategory}` : ""}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>Adresses IP</span>
                        <div style={{ color: "var(--tc-text)", fontFamily: "monospace" }}>{a.ip_addresses.join(", ") || "—"}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>MAC</span>
                        <div style={{ color: "var(--tc-text)", fontFamily: "monospace" }}>{a.mac_address || "—"} {a.mac_vendor && <span style={{ color: "var(--tc-text-muted)" }}>({a.mac_vendor})</span>}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>Hostname / FQDN</span>
                        <div style={{ color: "var(--tc-text)" }}>{a.hostname || "—"}{a.fqdn ? ` (${a.fqdn})` : ""}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>Système d{"'"}exploitation</span>
                        <div style={{ color: "var(--tc-text)" }}>{a.os || "—"} {a.os_confidence > 0 && a.os_confidence < 1 && <span style={{ color: "var(--tc-text-muted)" }}>({Math.round(a.os_confidence * 100)}%)</span>}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>Rôle</span>
                        <div style={{ color: "var(--tc-text)" }}>{a.role || "—"}</div>
                      </div>
                      {a.url && <div>
                        <span style={labelStyle}>URL</span>
                        <div style={{ color: "var(--tc-blue)", fontFamily: "monospace", fontSize: "9px" }}>{a.url}</div>
                      </div>}
                      <div>
                        <span style={labelStyle}>Responsable</span>
                        <div style={{ color: "var(--tc-text)" }}>{a.owner || "—"}</div>
                      </div>
                      <div>
                        <span style={labelStyle}>Localisation</span>
                        <div style={{ color: "var(--tc-text)" }}>{a.location || "—"}</div>
                      </div>
                    </div>

                    {/* Services */}
                    {a.services && Array.isArray(a.services) && a.services.length > 0 && (
                      <div style={{ marginTop: "12px", borderTop: "1px solid var(--tc-border)", paddingTop: "10px" }}>
                        <span style={labelStyle}>Services détectés</span>
                        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap", marginTop: "4px" }}>
                          {a.services.map((s: any, i: number) => (
                            <span key={i} style={{ fontSize: "9px", padding: "2px 6px", borderRadius: "3px", background: "var(--tc-input)", border: "1px solid var(--tc-border)", color: "var(--tc-text)", fontFamily: "monospace" }}>
                              {s.port}/{s.proto || "tcp"} {s.service || ""} {s.product || ""}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Tags */}
                    {a.tags.length > 0 && (
                      <div style={{ marginTop: "8px" }}>
                        <span style={labelStyle}>Tags</span>
                        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          {a.tags.map((t, i) => <span key={i} style={{ fontSize: "8px", padding: "1px 5px", borderRadius: "3px", background: "rgba(48,128,208,0.08)", color: "var(--tc-blue)", border: "1px solid rgba(48,128,208,0.15)" }}>{t}</span>)}
                        </div>
                      </div>
                    )}

                    {/* Notes */}
                    {a.notes && (
                      <div style={{ marginTop: "8px" }}>
                        <span style={labelStyle}>Notes</span>
                        <div style={{ fontSize: "10px", color: "var(--tc-text-sec)", fontStyle: "italic" }}>{a.notes}</div>
                      </div>
                    )}

                    {/* Metadata */}
                    <div style={{ marginTop: "10px", display: "flex", gap: "16px", fontSize: "9px", color: "var(--tc-text-muted)" }}>
                      <span>Source: {a.source}</span>
                      <span>Classification: {a.classification_method} ({Math.round(a.classification_confidence * 100)}%)</span>
                      <span>Première vue: {new Date(a.first_seen).toLocaleDateString("fr-FR")}</span>
                      <span>Dernière vue: {new Date(a.last_seen).toLocaleDateString("fr-FR")}</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ═══ Add/Edit Modal ═══ */}
      {showModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }}
          onClick={e => { if (e.target === e.currentTarget) setShowModal(false); }}>
          <div style={{ background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "24px", width: "520px", maxHeight: "85vh", overflowY: "auto" }}>

            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <h2 style={{ fontSize: "16px", fontWeight: 800, color: "var(--tc-text)", margin: 0 }}>
                {editAsset ? "Modifier l'asset" : modalStep === 0 ? "Quel type d'asset ?" : `Nouvel asset — ${activeCat?.label || ""}`}
              </h2>
              <button onClick={() => setShowModal(false)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)" }}><X size={16} /></button>
            </div>

            {/* Step 0: Category picker */}
            {modalStep === 0 && !editAsset && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                {categories.filter(c => c.id !== "unknown").map(cat => {
                  const Icon = ICON_MAP[cat.icon] || HelpCircle;
                  return (
                    <button key={cat.id} onClick={() => selectCategory(cat.id)} style={{
                      ...cardStyle, padding: "14px", cursor: "pointer", textAlign: "left" as const,
                      border: "1px solid var(--tc-border)", display: "flex", flexDirection: "column" as const, gap: "6px",
                      transition: "border-color 0.2s",
                    }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = cat.color)}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--tc-border)")}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <Icon size={18} color={cat.color} />
                        <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)" }}>
                          {locale === "en" ? (cat.label_en || cat.label) : cat.label}
                        </span>
                      </div>
                      <span style={{ fontSize: "9px", color: "var(--tc-text-muted)", lineHeight: "1.4" }}>
                        {CAT_DESCRIPTIONS[cat.id] || `Sous-types : ${cat.subcategories.join(", ")}`}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}

            {/* Step 1: Form adapted to category */}
            {(modalStep === 1 || editAsset) && (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>

                {/* Name */}
                <div>
                  <label style={labelStyle}>Nom de l{"'"}asset *</label>
                  <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                    placeholder={form.category === "website" ? "monsite.fr" : form.category === "server" ? "srv-web-01" : form.category === "workstation" ? "PC-COMPTA-01" : "Nom..."}
                    style={inputStyle} />
                </div>

                {/* Category + Criticality */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  <div>
                    <label style={labelStyle}>Catégorie</label>
                    <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value, subcategory: "" }))} style={inputStyle}>
                      {categories.map(c => <option key={c.id} value={c.id}>{c.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={labelStyle}>Criticité</label>
                    <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))} style={inputStyle}>
                      <option value="critical">Critique — essentiel au fonctionnement</option>
                      <option value="high">Haut — impact fort si compromis</option>
                      <option value="medium">Moyen — impact modéré</option>
                      <option value="low">Bas — impact limité</option>
                    </select>
                  </div>
                </div>

                {/* Subcategory (dynamic from selected category) */}
                {activeCat && activeCat.subcategories.length > 0 && (
                  <div>
                    <label style={labelStyle}>Sous-type / Rôle technique</label>
                    <select value={form.subcategory} onChange={e => setForm(f => ({ ...f, subcategory: e.target.value }))} style={inputStyle}>
                      <option value="">— Choisir —</option>
                      {activeCat.subcategories.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                )}

                {/* Role description */}
                <div>
                  <label style={labelStyle}>Description du rôle</label>
                  <input value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                    placeholder={form.category === "server" ? "Ex: Serveur de base de données PostgreSQL production" : form.category === "website" ? "Ex: Site vitrine WordPress avec WooCommerce" : "Que fait cet asset dans votre infrastructure ?"}
                    style={inputStyle} />
                </div>

                {/* URL (websites only) */}
                {(form.category === "website" || form.url) && (
                  <div>
                    <label style={labelStyle}>URL</label>
                    <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                      placeholder="https://monsite.fr" style={inputStyle} />
                  </div>
                )}

                {/* IP + Hostname (not for websites unless on-premise) */}
                {form.category !== "website" && (
                  <>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                      <div>
                        <label style={labelStyle}>Adresse(s) IP</label>
                        <input value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))}
                          placeholder="192.168.1.10 (ou plusieurs séparées par ,)" style={inputStyle} />
                      </div>
                      <div>
                        <label style={labelStyle}>Hostname</label>
                        <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
                          placeholder={form.category === "workstation" ? "PC-COMPTA-01" : "srv-web-01"} style={inputStyle} />
                      </div>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                      <div>
                        <label style={labelStyle}>Adresse MAC</label>
                        <input value={form.mac} onChange={e => setForm(f => ({ ...f, mac: e.target.value }))}
                          placeholder="00:1A:2B:3C:4D:5E (optionnel)" style={inputStyle} />
                      </div>
                      <div>
                        <label style={labelStyle}>Système d{"'"}exploitation</label>
                        <input value={form.os} onChange={e => setForm(f => ({ ...f, os: e.target.value }))}
                          placeholder={form.category === "network" ? "FortiOS 7.4" : form.category === "ot" ? "Firmware v2.1" : "Ubuntu 22.04 / Windows Server 2022"} style={inputStyle} />
                      </div>
                    </div>
                  </>
                )}

                {/* Website: special fields */}
                {form.category === "website" && (
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                    <div>
                      <label style={labelStyle}>Adresse IP (si on-premise)</label>
                      <input value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))} placeholder="Optionnel" style={inputStyle} />
                    </div>
                    <div>
                      <label style={labelStyle}>Hostname serveur</label>
                      <input value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} placeholder="Optionnel" style={inputStyle} />
                    </div>
                  </div>
                )}

                {/* Owner + Location */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px" }}>
                  <div>
                    <label style={labelStyle}>Responsable</label>
                    <input value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} placeholder="Jean Dupont / Équipe Infra" style={inputStyle} />
                  </div>
                  <div>
                    <label style={labelStyle}>Localisation</label>
                    <input value={form.location} onChange={e => setForm(f => ({ ...f, location: e.target.value }))} placeholder="Bureau Paris / Datacenter OVH" style={inputStyle} />
                  </div>
                </div>

                {/* Notes */}
                <div>
                  <label style={labelStyle}>Notes</label>
                  <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
                    placeholder="Informations complémentaires pour le RSSI..."
                    style={{ ...inputStyle, minHeight: "50px", resize: "vertical" }} />
                </div>

                {/* Buttons */}
                <div style={{ display: "flex", justifyContent: "space-between", marginTop: "8px" }}>
                  {!editAsset && (
                    <button onClick={() => setModalStep(0)} style={btnSecondary}>
                      <ChevronLeft size={12} /> Changer de catégorie
                    </button>
                  )}
                  <button onClick={handleSave} disabled={!form.name} style={{
                    ...btnPrimary, marginLeft: "auto",
                    opacity: form.name ? 1 : 0.5, cursor: form.name ? "pointer" : "default",
                  }}>
                    <CheckCircle2 size={13} /> {editAsset ? "Mettre à jour" : "Ajouter"}
                  </button>
                </div>

                {/* Hint */}
                <div style={{ fontSize: "9px", color: "var(--tc-text-muted)", fontStyle: "italic", marginTop: "4px" }}>
                  ThreatClaw enrichira automatiquement cet asset (ports, services, OS) lors du prochain scan réseau.
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
