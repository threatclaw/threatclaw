"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";
import { X, Maximize2, Minimize2, Eye, EyeOff } from "lucide-react";
import { NeuCard } from "./NeuCard";

// ── SVG icon paths (16x16 viewBox) ──
const ICONS: Record<string, string> = {
  ip:        "M8 1a7 7 0 100 14A7 7 0 008 1zm0 1.5a5.5 5.5 0 110 11 5.5 5.5 0 010-11zM5 5l6 6M11 5L5 11", // globe + X
  asset:     "M2 4h12v9H2V4zm1 1v7h10V5H3zm2-3h6v2H5V2zm1 6h4v2H6V8z", // server rack
  cve:       "M8 1L1 15h14L8 1zm0 4v4m0 2v1", // warning triangle
  technique: "M8 2l6 3.5v5L8 14l-6-3.5v-5L8 2zm0 3v4m-3-2h6", // diamond grid
  actor:     "M8 2a3 3 0 100 6 3 3 0 000-6zM4 12c0-2.2 1.8-4 4-4s4 1.8 4 4", // person
  campaign:  "M4 2v12l4-3 4 3V2H4z", // flag
  server:    "M3 3h10v3H3V3zm0 4h10v3H3V7zm0 4h10v3H3v-3zm7-7h1v1h-1V4zm0 4h1v1h-1V8zm0 4h1v1h-1v-1z", // rack + LEDs
  workstation: "M4 3h8v6H4V3zm2 7h4v1H6v-1zm1 1h2v2H7v-2z", // monitor
  website:   "M8 1a7 7 0 100 14A7 7 0 008 1zM1.5 8h13M8 1.5c-2 2-3 4-3 6.5s1 4.5 3 6.5c2-2 3-4 3-6.5S10 3.5 8 1.5z", // globe
  database:  "M4 4c0-1.1 1.8-2 4-2s4 .9 4 2v8c0 1.1-1.8 2-4 2s-4-.9-4-2V4zm0 4c0 1.1 1.8 2 4 2s4-.9 4-2M4 8c0 1.1 1.8 2 4 2s4-.9 4-2", // cylinder
  network:   "M8 2L2 6l6 4 6-4-6-4zM2 10l6 4 6-4", // network layers
  printer:   "M5 2h6v3H5V2zm-2 3h10v6H3V5zm2 4h6v4H5V9z", // printer
  iot:       "M6 4h4v8H6V4zm-2 2h2v4H4V6zm6 0h2v4h-2V6zm-4-4h4v2H6V2zm0 10h4v2H6v-2z", // chip
  camera:    "M1 5h3l1-2h6l1 2h3v8H1V5zm7 1a3 3 0 100 6 3 3 0 000-6z", // camera
  unknown:   "M8 1a7 7 0 100 14A7 7 0 008 1zm0 3a2.5 2.5 0 011 4.8V10H7V8.8A2.5 2.5 0 018 4zm0 8a1 1 0 100-2 1 1 0 000 2z", // question
};

// Map asset subcategories to icon keys
const NODE_ICON_MAP: Record<string, string> = {
  ip: "ip", asset: "server", cve: "cve", technique: "technique",
  actor: "actor", campaign: "campaign",
  // Asset subcategories
  server: "server", web: "server", db: "database", mail: "server",
  dns: "network", ad: "server", file: "server",
  workstation: "workstation", desktop: "workstation", laptop: "workstation",
  website: "website", wordpress: "website", prestashop: "website",
  network: "network", firewall: "network", switch: "network", routeur: "network",
  printer: "printer", iot: "iot", camera: "camera",
  ot: "iot", plc: "iot", cloud: "website", unknown: "unknown",
};

const NODE_COLORS: Record<string, string> = {
  ip: "#e04040", asset: "#3080d0", cve: "#d09020",
  technique: "#9060d0", actor: "#d06020", campaign: "#30a050",
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

function makeSvgDataUrl(pathD: string, color: string, size: number = 16): string {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 16 16"><path d="${pathD}" fill="none" stroke="${encodeURIComponent(color)}" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  return `data:image/svg+xml,${svg}`;
}

interface NodeDetail {
  id: string; label: string; nodeType: string;
  criticality?: string; hostname?: string; cvss?: number;
  tactic?: string; classification?: string; subcategory?: string;
  mlScore?: number; mlReason?: string;
  relations: { target: string; type: string; direction: string }[];
}

export default function GraphVisualization() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });
  const [error, setError] = useState<string | null>(null);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [simplified, setSimplified] = useState(true);

  const nodesDataRef = useRef<Map<string, any>>(new Map());
  const edgesDataRef = useRef<any[]>([]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (selectedNode) setSelectedNode(null);
        else if (fullscreen) setFullscreen(false);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedNode, fullscreen]);

  const loadAndRender = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelectedNode(null);

    try {
      const [r1, r2, r3, r4] = await Promise.all([
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, ip.classification, asset.hostname, asset.id, asset.type, asset.criticality, a.method LIMIT 100" }),
          signal: AbortSignal.timeout(10000),
        }),
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) RETURN c.id, c.cvss, a.id, a.hostname LIMIT 50" }),
          signal: AbortSignal.timeout(10000),
        }),
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (t:Technique) RETURN t.mitre_id, t.name, t.tactic LIMIT 30" }),
          signal: AbortSignal.timeout(10000),
        }),
        // Fetch ML scores for assets
        fetch("/api/tc/assets?limit=200", { signal: AbortSignal.timeout(10000) }).catch(() => null),
      ]);

      const d1 = await r1.json(), d2 = await r2.json(), d3 = await r3.json();
      const assetsData = r4 ? await r4.json().catch(() => ({})) : {};
      const assetsList = assetsData.assets || [];

      const nodeMap = new Map<string, any>();
      const edgeList: any[] = [];
      const types = new Set<string>();
      const relCount = new Map<string, number>();
      const incRel = (id: string) => relCount.set(id, (relCount.get(id) || 0) + 1);

      // IP → Asset
      for (const r of (d1.results || [])) {
        const ip = r["ip.addr"] || "", aid = r["asset.id"] || "";
        const ah = r["asset.hostname"] || aid, crit = r["asset.criticality"] || "medium";
        const assetType = r["asset.type"] || "server";
        const cls = r["ip.classification"] || "";

        if (ip && !nodeMap.has(ip)) {
          types.add("ip");
          nodeMap.set(ip, { id: ip, data: { label: ip, nodeType: "ip", classification: cls, subcategory: "ip" } });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          const label = ah.length > 18 ? ah.slice(0, 16) + "…" : ah;
          const assetInfo = assetsList.find((a: any) => a.id === aid);
          nodeMap.set(aid, {
            id: aid, data: {
              label, nodeType: "asset", criticality: crit, hostname: ah,
              subcategory: assetInfo?.subcategory || assetType,
              mlScore: assetInfo?.ml_score,
            }
          });
        }
        if (ip && aid) {
          const lateral = ip.startsWith("192.168.") || ip.startsWith("10.");
          const eid = `${ip}>${aid}>${lateral ? "L" : "A"}`;
          if (!edgeList.find(e => e.id === eid)) {
            edgeList.push({ id: eid, source: ip, target: aid, data: { edgeType: lateral ? "LATERAL" : "ATTACKS" } });
            incRel(ip); incRel(aid);
          }
        }
      }

      // CVE → Asset
      for (const r of (d2.results || [])) {
        const cid = r["c.id"] || "", cvss = parseFloat(r["c.cvss"]) || 0;
        const aid = r["a.id"] || "", ah = r["a.hostname"] || "";
        if (cid && !nodeMap.has(cid)) {
          types.add("cve");
          nodeMap.set(cid, { id: cid, data: { label: cid, nodeType: "cve", cvss, subcategory: "cve" } });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          nodeMap.set(aid, { id: aid, data: { label: ah || aid.slice(0, 12), nodeType: "asset", subcategory: "server" } });
        }
        if (cid && aid) {
          const eid = `${cid}>${aid}>AFF`;
          if (!edgeList.find(e => e.id === eid)) {
            edgeList.push({ id: eid, source: cid, target: aid, data: { edgeType: "AFFECTS" } });
            incRel(cid); incRel(aid);
          }
        }
      }

      // Techniques
      if (!simplified) {
        const attackedAssets = new Set(edgeList.filter(e => e.data.edgeType === "ATTACKS" || e.data.edgeType === "LATERAL").map(e => e.target));
        for (const r of (d3.results || [])) {
          const tid = r["t.mitre_id"] || "", tname = r["t.name"] || "", tactic = r["t.tactic"] || "";
          if (tid && !nodeMap.has(tid)) {
            types.add("technique");
            nodeMap.set(tid, { id: tid, data: { label: tname.length > 14 ? tname.slice(0, 12) + "…" : tname || tid, nodeType: "technique", tactic, fullName: tname, subcategory: "technique" } });
            const targets = Array.from(attackedAssets);
            if (targets.length > 0) {
              const target = targets[Math.floor(Math.random() * targets.length)];
              edgeList.push({ id: `${tid}>${target}>USES`, source: tid, target, data: { edgeType: "USES" } });
              incRel(tid); incRel(target);
            }
          }
        }
      }

      nodesDataRef.current = nodeMap;
      edgesDataRef.current = edgeList;

      const nodes = Array.from(nodeMap.values());
      setStats({ nodes: nodes.length, edges: edgeList.length });
      setActiveTypes(types);

      if (nodes.length === 0) { setLoading(false); return; }

      if (graphRef.current) { try { graphRef.current.destroy(); } catch {} graphRef.current = null; }
      const el = document.getElementById("g6-container");
      if (el) el.innerHTML = "";

      const { Graph } = await import("@antv/g6");
      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      const w = (containerRef.current?.clientWidth || 640) - (selectedNode ? 292 : 32);
      const h = fullscreen ? window.innerHeight - 60 : 450;

      const graph = new Graph({
        container: "g6-container",
        width: w, height: h,
        autoFit: "view",
        padding: 50,
        data: { nodes, edges: edgeList },
        layout: { type: "dagre", rankdir: "LR", nodesep: 60, ranksep: 120 },
        node: {
          type: "circle",
          style: {
            size: (d: any) => {
              const base = d.data?.nodeType === "technique" ? 20 : d.data?.nodeType === "cve" ? 24 : 30;
              const rels = relCount.get(d.id) || 0;
              const critBonus = d.data?.criticality === "critical" ? 14 : d.data?.criticality === "high" ? 8 : 0;
              return base + rels * 6 + critBonus;
            },
            fill: (d: any) => {
              const color = NODE_COLORS[d.data?.nodeType] || "#888";
              return color + "20"; // semi-transparent fill
            },
            stroke: (d: any) => NODE_COLORS[d.data?.nodeType] || "#888",
            lineWidth: 2.5,
            iconSrc: (d: any) => {
              const sub = d.data?.subcategory || d.data?.nodeType || "unknown";
              const iconKey = NODE_ICON_MAP[sub] || NODE_ICON_MAP[d.data?.nodeType] || "unknown";
              const color = isLight ? (NODE_COLORS[d.data?.nodeType] || "#555") : "#fff";
              return makeSvgDataUrl(ICONS[iconKey] || ICONS.unknown, color);
            },
            iconWidth: 16, iconHeight: 16,
            labelText: (d: any) => d.data?.label || d.id,
            labelFontSize: 11, labelFontWeight: 600,
            labelFill: isLight ? "#111" : "#eee",
            labelPlacement: "bottom", labelOffsetY: 10,
            labelFontFamily: "Inter, sans-serif",
          },
          state: {
            active: { stroke: "#fff", lineWidth: 3, shadowBlur: 12, shadowColor: "rgba(255,255,255,0.3)" },
            inactive: { opacity: 0.2 },
          },
        },
        edge: {
          type: "line",
          style: {
            stroke: (d: any) => EDGE_COLORS[d.data?.edgeType] || "rgba(150,150,150,0.4)",
            lineWidth: 2, endArrow: true, endArrowSize: 8,
            labelText: (d: any) => d.data?.edgeType || "",
            labelFontSize: 10, labelFontWeight: 600,
            labelFill: isLight ? "#222" : "#ddd",
            labelBackground: true,
            labelBackgroundFill: isLight ? "rgba(255,255,255,0.85)" : "rgba(0,0,0,0.7)",
            labelBackgroundRadius: 3,
            labelPadding: [1, 4, 1, 4],
            labelFontFamily: "Inter, sans-serif",
          },
          state: {
            active: { lineWidth: 3, endArrowSize: 10 },
            inactive: { opacity: 0.08 },
          },
        },
        behaviors: [
          "drag-canvas", "zoom-canvas", "drag-element",
          { type: "hover-activate", degree: 1, state: "active", inactiveState: "inactive" },
        ],
        plugins: [{
          type: "tooltip",
          getContent: (_: any, items: any[]) => {
            if (!items?.[0]) return "";
            const d = items[0].data || {};
            const nt = d.nodeType || "node";
            const color = NODE_COLORS[nt] || "#888";
            const rels = edgeList.filter(e => e.source === items[0].id || e.target === items[0].id).length;
            let html = `<div style="font-size:13px;font-weight:800;color:${color};margin-bottom:3px">${d.label || items[0].id}</div>`;
            html += `<div style="font-size:9px;color:#888;text-transform:uppercase;margin-bottom:6px">${nt}${d.subcategory && d.subcategory !== nt ? " · " + d.subcategory : ""}</div>`;
            if (d.criticality) html += `<div style="font-size:11px">Criticité : <b style="color:${d.criticality === "critical" ? "#e04040" : d.criticality === "high" ? "#d07020" : "#888"}">${d.criticality}</b></div>`;
            if (d.hostname) html += `<div style="font-size:11px">Hostname : <b>${d.hostname}</b></div>`;
            if (d.cvss) html += `<div style="font-size:11px">CVSS : <b style="color:${d.cvss >= 9 ? "#e04040" : "#d09020"}">${d.cvss}</b></div>`;
            if (d.tactic) html += `<div style="font-size:11px">Tactique : <b>${d.tactic}</b></div>`;
            if (d.classification) html += `<div style="font-size:11px">Type : <b>${d.classification}</b></div>`;
            html += `<div style="font-size:10px;color:#888;margin-top:4px;border-top:1px solid rgba(150,150,150,0.2);padding-top:3px">${rels} relation(s) · clic pour détails</div>`;
            return html;
          },
        }],
      });

      graph.on("node:click", (evt: any) => {
        const nodeId = evt.target?.id; if (!nodeId) return;
        const nd = nodeMap.get(nodeId); if (!nd) return;
        const d = nd.data || {};
        const rels = edgeList.filter(e => e.source === nodeId || e.target === nodeId)
          .map(e => ({ target: e.source === nodeId ? e.target : e.source, type: e.data?.edgeType || "?", direction: e.source === nodeId ? "→" : "←" }));
        setSelectedNode({
          id: nodeId, label: d.label || nodeId, nodeType: d.nodeType || "node",
          criticality: d.criticality, hostname: d.hostname, cvss: d.cvss,
          tactic: d.tactic, classification: d.classification, subcategory: d.subcategory,
          mlScore: d.mlScore, relations: rels,
        });
      });
      graph.on("canvas:click", () => setSelectedNode(null));

      await graph.render();
      graphRef.current = graph;
    } catch (e: any) {
      console.error("Graph:", e);
      setError(e.message || "Erreur");
    }
    setLoading(false);
  }, [fullscreen, simplified, selectedNode]);

  useEffect(() => {
    loadAndRender();
    return () => { if (graphRef.current) try { graphRef.current.destroy(); } catch {} };
  }, [loadAndRender]);

  const nodeStyle = selectedNode ? { color: NODE_COLORS[selectedNode.nodeType] || "#888" } : null;

  return (
    <div ref={containerRef} style={fullscreen ? {
      background: "var(--tc-bg)", padding: "16px", position: "fixed",
      top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999,
    } : {
      // NeuCard inline style (same as NeuCard component)
      padding: "2px", borderRadius: "var(--tc-radius-md)", overflow: "visible", position: "relative",
      backgroundColor: "var(--tc-neu-outer)",
      boxShadow: "inset 0 3px 8px rgba(0,0,0,0.45), inset 0 1px 3px rgba(0,0,0,0.35), inset 0 -1px 1px rgba(255,255,255,0.06), 0 1px 0 rgba(255,255,255,0.12)",
    }}>
    <div style={fullscreen ? {} : {
      borderRadius: "calc(var(--tc-radius-md) - 2px)", padding: "16px", position: "relative",
      backgroundColor: "var(--tc-neu-inner)",
      boxShadow: "inset 0 4px 10px rgba(0,0,0,0.4), inset 0 2px 4px rgba(0,0,0,0.3), inset 0 -2px 4px rgba(255,255,255,0.04)",
      color: "var(--tc-neu-text)",
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Graphe d&apos;attaque
          </span>
          {/* Simplified toggle */}
          <button onClick={() => setSimplified(!simplified)} style={{
            background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 8px", display: "flex", alignItems: "center", gap: 4, fontSize: 9,
          }} title={simplified ? "Vue complète (avec techniques)" : "Vue simplifiée"}>
            {simplified ? <Eye size={11} /> : <EyeOff size={11} />}
            {simplified ? "Simple" : "Complet"}
          </button>
          <button onClick={() => setFullscreen(!fullscreen)} style={{
            background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 6px", display: "flex", alignItems: "center",
          }} title={fullscreen ? "Réduire" : "Plein écran"}>
            {fullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_COLORS).filter(([t]) => activeTypes.has(t)).map(([type, color]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block", border: `1px solid ${color}` }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Chargement...</div>}
      {error && <div style={{ textAlign: "center", padding: "40px 0", color: "#d03020", fontSize: 11 }}>{error}</div>}
      {!loading && stats.nodes === 0 && !error && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Aucune donnée. Lancez un test.</div>}

      <div style={{ display: "flex", gap: 0 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div id="g6-container" style={{ width: "100%", minHeight: loading || stats.nodes === 0 ? 0 : fullscreen ? "calc(100vh - 60px)" : 450 }} />
        </div>

        {/* Side panel */}
        {selectedNode && (
          <div style={{
            width: 260, flexShrink: 0, borderLeft: "1px solid var(--tc-border)",
            padding: "16px", overflowY: "auto", maxHeight: fullscreen ? "calc(100vh - 60px)" : 450,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: nodeStyle?.color, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {selectedNode.nodeType}{selectedNode.subcategory && selectedNode.subcategory !== selectedNode.nodeType ? ` · ${selectedNode.subcategory}` : ""}
              </span>
              <button onClick={() => setSelectedNode(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: 2 }}><X size={14} /></button>
            </div>

            <div style={{ fontSize: 16, fontWeight: 800, color: "var(--tc-text)", marginBottom: 12, wordBreak: "break-all" }}>
              {selectedNode.label}
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 11 }}>
              {selectedNode.criticality && (
                <Row label="Criticité" value={selectedNode.criticality.toUpperCase()} color={selectedNode.criticality === "critical" ? "#e04040" : selectedNode.criticality === "high" ? "#d07020" : undefined} />
              )}
              {selectedNode.hostname && selectedNode.hostname !== selectedNode.label && (
                <Row label="Hostname" value={selectedNode.hostname} mono />
              )}
              {selectedNode.cvss !== undefined && selectedNode.cvss > 0 && (
                <Row label="CVSS" value={String(selectedNode.cvss)} color={selectedNode.cvss >= 9 ? "#e04040" : "#d09020"} />
              )}
              {selectedNode.tactic && <Row label="Tactique" value={selectedNode.tactic} />}
              {selectedNode.classification && <Row label="Type" value={selectedNode.classification} />}

              {/* ML Score */}
              {selectedNode.mlScore !== undefined && selectedNode.mlScore > 0 && (
                <div style={{
                  marginTop: 4, padding: "8px 10px", borderRadius: "var(--tc-radius-sm)",
                  background: selectedNode.mlScore > 0.7 ? "rgba(224,64,64,0.1)" : selectedNode.mlScore > 0.3 ? "rgba(208,144,32,0.1)" : "rgba(48,160,80,0.1)",
                  border: `1px solid ${selectedNode.mlScore > 0.7 ? "rgba(224,64,64,0.2)" : selectedNode.mlScore > 0.3 ? "rgba(208,144,32,0.2)" : "rgba(48,160,80,0.2)"}`,
                }}>
                  <div style={{ fontSize: 9, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 3 }}>Score ML</div>
                  <div style={{
                    fontSize: 18, fontWeight: 900,
                    color: selectedNode.mlScore > 0.7 ? "#e04040" : selectedNode.mlScore > 0.3 ? "#d09020" : "#30a050",
                  }}>
                    {Math.round(selectedNode.mlScore * 100)}%
                  </div>
                  {selectedNode.mlReason && <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 2 }}>{selectedNode.mlReason}</div>}
                </div>
              )}
            </div>

            {selectedNode.relations.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
                  Relations ({selectedNode.relations.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedNode.relations.map((rel, i) => {
                    const td = nodesDataRef.current.get(rel.target);
                    const tl = td?.data?.label || rel.target;
                    const tt = td?.data?.nodeType || "?";
                    return (
                      <div key={i} style={{
                        display: "flex", alignItems: "center", gap: 6, padding: "4px 6px",
                        background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", fontSize: 10,
                      }}>
                        <span style={{ color: EDGE_COLORS[rel.type] || "var(--tc-text-muted)", fontWeight: 700, fontSize: 8, minWidth: 55 }}>
                          {rel.direction} {rel.type}
                        </span>
                        <span style={{ color: NODE_COLORS[tt] || "var(--tc-text)", fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {tl.length > 18 ? tl.slice(0, 16) + "…" : tl}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {stats.nodes > 0 && !loading && (
        <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 6, textAlign: "center" }}>
          {stats.nodes} noeuds · {stats.edges} relations — hover = détail · clic = panneau · ESC = fermer · molette = zoom
        </div>
      )}
    </div>
    </div>
  );
}

function Row({ label, value, color, mono }: { label: string; value: string; color?: string; mono?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between" }}>
      <span style={{ color: "var(--tc-text-muted)" }}>{label}</span>
      <span style={{ fontWeight: 700, color: color || "var(--tc-text)", fontFamily: mono ? "monospace" : "inherit", fontSize: mono ? 10 : 11 }}>{value}</span>
    </div>
  );
}
