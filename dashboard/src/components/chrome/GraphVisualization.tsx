"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";
import { X, Shield, AlertTriangle, Cpu, Target, Users, Flag, Maximize2, Minimize2 } from "lucide-react";

const NODE_STYLES: Record<string, { color: string; shape: string; label: string; icon: React.ElementType }> = {
  ip:        { color: "#e04040", shape: "diamond",  label: "IP",        icon: AlertTriangle },
  asset:     { color: "#3080d0", shape: "rect",     label: "Asset",     icon: Shield },
  cve:       { color: "#d09020", shape: "triangle", label: "CVE",       icon: Target },
  technique: { color: "#9060d0", shape: "diamond",  label: "Technique", icon: Cpu },
  actor:     { color: "#d06020", shape: "hexagon",  label: "Acteur",    icon: Users },
  campaign:  { color: "#30a050", shape: "rect",     label: "Campagne",  icon: Flag },
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

interface NodeDetail {
  id: string;
  label: string;
  nodeType: string;
  criticality?: string;
  hostname?: string;
  cvss?: number;
  tactic?: string;
  classification?: string;
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

  // ESC key handler
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

  // Store raw data for panel lookups
  const nodesDataRef = useRef<Map<string, any>>(new Map());
  const edgesDataRef = useRef<any[]>([]);

  const loadAndRender = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelectedNode(null);

    try {
      const [r1, r2, r3] = await Promise.all([
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, ip.classification, asset.hostname, asset.id, asset.criticality, a.method LIMIT 100" }),
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
      ]);

      const d1 = await r1.json(), d2 = await r2.json(), d3 = await r3.json();
      const nodeMap = new Map<string, any>();
      const edgeList: any[] = [];
      const types = new Set<string>();
      // Count relations per node for sizing
      const relCount = new Map<string, number>();
      const incRel = (id: string) => relCount.set(id, (relCount.get(id) || 0) + 1);

      // IP → Asset
      for (const r of (d1.results || [])) {
        const ip = r["ip.addr"] || "", aid = r["asset.id"] || "";
        const ah = r["asset.hostname"] || aid, crit = r["asset.criticality"] || "medium";
        const cls = r["ip.classification"] || "";

        if (ip && !nodeMap.has(ip)) {
          types.add("ip");
          nodeMap.set(ip, { id: ip, data: { label: ip, nodeType: "ip", classification: cls } });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          nodeMap.set(aid, { id: aid, data: { label: ah.length > 18 ? ah.slice(0, 16) + "…" : ah, nodeType: "asset", criticality: crit, hostname: ah } });
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
          nodeMap.set(cid, { id: cid, data: { label: cid, nodeType: "cve", cvss } });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          nodeMap.set(aid, { id: aid, data: { label: ah || aid.slice(0, 12), nodeType: "asset" } });
        }
        if (cid && aid) {
          const eid = `${cid}>${aid}>AFF`;
          if (!edgeList.find(e => e.id === eid)) {
            edgeList.push({ id: eid, source: cid, target: aid, data: { edgeType: "AFFECTS" } });
            incRel(cid); incRel(aid);
          }
        }
      }

      // Techniques — link to assets that have attacks (via shared alerts)
      // For now, connect techniques to assets that are under attack
      const attackedAssets = new Set(edgeList.filter(e => e.data.edgeType === "ATTACKS" || e.data.edgeType === "LATERAL").map(e => e.target));
      for (const r of (d3.results || [])) {
        const tid = r["t.mitre_id"] || "", tname = r["t.name"] || "", tactic = r["t.tactic"] || "";
        if (tid && !nodeMap.has(tid)) {
          types.add("technique");
          nodeMap.set(tid, { id: tid, data: { label: tname.length > 14 ? tname.slice(0, 12) + "…" : tname || tid, nodeType: "technique", tactic, fullName: tname } });
          // Connect technique to attacked assets (distribute)
          const targets = Array.from(attackedAssets);
          if (targets.length > 0) {
            const target = targets[Math.floor(Math.random() * targets.length)]; // random assignment for now
            const eid = `${tid}>${target}>USES`;
            edgeList.push({ id: eid, source: tid, target, data: { edgeType: "USES" } });
            incRel(tid); incRel(target);
          }
        }
      }

      // Store for panel
      nodesDataRef.current = nodeMap;
      edgesDataRef.current = edgeList;

      const nodes = Array.from(nodeMap.values());
      setStats({ nodes: nodes.length, edges: edgeList.length });
      setActiveTypes(types);

      if (nodes.length === 0) { setLoading(false); return; }

      // Destroy previous
      if (graphRef.current) { try { graphRef.current.destroy(); } catch {} graphRef.current = null; }
      const el = document.getElementById("g6-container");
      if (el) el.innerHTML = "";

      const { Graph } = await import("@antv/g6");
      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      const w = (containerRef.current?.clientWidth || 640) - 32;

      const graph = new Graph({
        container: "g6-container",
        width: w,
        height: fullscreen ? window.innerHeight - 60 : 450,
        autoFit: "view",
        padding: 40,
        data: { nodes, edges: edgeList },
        layout: { type: "dagre", rankdir: "LR", nodesep: 50, ranksep: 100 },
        node: {
          type: (d: any) => NODE_STYLES[d.data?.nodeType]?.shape || "circle",
          style: {
            size: (d: any) => {
              const base = d.data?.nodeType === "technique" ? 16 : d.data?.nodeType === "cve" ? 20 : 24;
              const rels = relCount.get(d.id) || 0;
              const critBonus = d.data?.criticality === "critical" ? 12 : d.data?.criticality === "high" ? 8 : 0;
              return base + rels * 4 + critBonus;
            },
            fill: (d: any) => NODE_STYLES[d.data?.nodeType]?.color || "#888",
            stroke: (d: any) => NODE_STYLES[d.data?.nodeType]?.color || "#888",
            lineWidth: 2, radius: 6,
            labelText: (d: any) => d.data?.label || d.id,
            labelFontSize: 11, labelFontWeight: 600, labelFill: isLight ? "#111" : "#eee",
            labelPlacement: "bottom", labelOffsetY: 8, labelFontFamily: "Inter, sans-serif",
          },
          state: {
            active: { stroke: "#fff", lineWidth: 3 },
            inactive: { opacity: 0.25 },
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
            active: { lineWidth: 3 },
            inactive: { opacity: 0.1 },
          },
        },
        behaviors: [
          "drag-canvas", "zoom-canvas", "drag-element",
          { type: "hover-activate", degree: 1, state: "active", inactiveState: "inactive" },
        ],
        plugins: [
          {
            type: "tooltip",
            getContent: (_: any, items: any[]) => {
              if (!items || !items[0]) return "";
              const d = items[0].data || {};
              const nt = d.nodeType || "node";
              const color = NODE_STYLES[nt]?.color || "#888";
              let html = `<div style="font-size:12px;font-weight:700;color:${color};margin-bottom:3px">${d.label || items[0].id}</div>`;
              html += `<div style="font-size:8px;color:#888;text-transform:uppercase;margin-bottom:5px">${NODE_STYLES[nt]?.label || nt}</div>`;
              if (d.criticality) html += `<div style="font-size:10px">Criticité : <b>${d.criticality}</b></div>`;
              if (d.hostname) html += `<div style="font-size:10px">Hostname : <b>${d.hostname}</b></div>`;
              if (d.cvss) html += `<div style="font-size:10px">CVSS : <b>${d.cvss}</b></div>`;
              if (d.tactic) html += `<div style="font-size:10px">Tactique : <b>${d.tactic}</b></div>`;
              if (d.classification) html += `<div style="font-size:10px">Classification : <b>${d.classification}</b></div>`;
              const rels = edgeList.filter(e => e.source === items[0].id || e.target === items[0].id).length;
              html += `<div style="font-size:9px;color:#888;margin-top:4px">${rels} relation(s)</div>`;
              return html;
            },
          },
        ],
      });

      // Click handler for side panel
      graph.on("node:click", (evt: any) => {
        const nodeId = evt.target?.id;
        if (!nodeId) return;
        const nodeData = nodeMap.get(nodeId);
        if (!nodeData) return;
        const d = nodeData.data || {};
        const rels = edgeList
          .filter(e => e.source === nodeId || e.target === nodeId)
          .map(e => ({
            target: e.source === nodeId ? e.target : e.source,
            type: e.data?.edgeType || "?",
            direction: e.source === nodeId ? "→" : "←",
          }));
        setSelectedNode({
          id: nodeId, label: d.label || nodeId, nodeType: d.nodeType || "node",
          criticality: d.criticality, hostname: d.hostname, cvss: d.cvss,
          tactic: d.tactic, classification: d.classification, relations: rels,
        });
      });

      // Click on canvas background to close panel
      graph.on("canvas:click", () => setSelectedNode(null));

      await graph.render();
      graphRef.current = graph;
    } catch (e: any) {
      console.error("Graph error:", e);
      setError(e.message || "Erreur rendu");
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    loadAndRender();
    return () => { if (graphRef.current) try { graphRef.current.destroy(); } catch {} };
  }, [loadAndRender]);

  const nodeStyle = selectedNode ? NODE_STYLES[selectedNode.nodeType] : null;

  // Re-render graph when toggling fullscreen
  useEffect(() => {
    if (!loading && stats.nodes > 0) {
      const timer = setTimeout(() => loadAndRender(), 100);
      return () => clearTimeout(timer);
    }
  }, [fullscreen]);

  return (
    <div ref={containerRef} style={{
      background: fullscreen ? "var(--tc-bg)" : "var(--tc-surface-alt)",
      border: fullscreen ? "none" : "1px solid var(--tc-border)",
      borderRadius: fullscreen ? 0 : "var(--tc-radius-md)",
      padding: "16px", position: fullscreen ? "fixed" : "relative",
      ...(fullscreen ? { top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999 } : {}),
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Graphe d&apos;attaque
          </span>
          <button onClick={() => setFullscreen(!fullscreen)} style={{
            background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 6px", display: "flex", alignItems: "center",
          }} title={fullscreen ? "Réduire" : "Plein écran"}>
            {fullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_STYLES)
            .filter(([type]) => activeTypes.has(type))
            .map(([type, s]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: s.shape === "rect" ? "2px" : "50%", background: s.color, display: "inline-block", transform: s.shape === "diamond" ? "rotate(45deg) scale(0.7)" : "none" }} />
              {s.label}
            </span>
          ))}
        </div>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Chargement...</div>}
      {error && <div style={{ textAlign: "center", padding: "40px 0", color: "#d03020", fontSize: 11 }}>{error}</div>}
      {!loading && stats.nodes === 0 && !error && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Aucune donnée. Lancez un test.</div>}

      {/* Graph + Side panel layout */}
      <div style={{ display: "flex", gap: 0 }}>
        {/* Graph */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div id="g6-container" style={{ width: "100%", minHeight: loading || stats.nodes === 0 ? 0 : fullscreen ? "calc(100vh - 60px)" : 450 }} />
        </div>

        {/* Side detail panel */}
        {selectedNode && (
          <div style={{
            width: "260px", flexShrink: 0, borderLeft: "1px solid var(--tc-border)",
            padding: "16px", overflowY: "auto", maxHeight: "450px",
          }}>
            {/* Close */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: nodeStyle?.color || "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {nodeStyle?.label || selectedNode.nodeType}
              </span>
              <button onClick={() => setSelectedNode(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)" }}>
                <X size={14} />
              </button>
            </div>

            {/* Name */}
            <div style={{ fontSize: 16, fontWeight: 800, color: "var(--tc-text)", marginBottom: 12, wordBreak: "break-all" }}>
              {selectedNode.label}
            </div>

            {/* Attributes */}
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 11 }}>
              {selectedNode.criticality && (
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>Criticité</span>
                  <span style={{ fontWeight: 700, color: selectedNode.criticality === "critical" ? "#e04040" : selectedNode.criticality === "high" ? "#d07020" : "var(--tc-text)" }}>
                    {selectedNode.criticality.toUpperCase()}
                  </span>
                </div>
              )}
              {selectedNode.hostname && selectedNode.hostname !== selectedNode.label && (
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>Hostname</span>
                  <span style={{ fontWeight: 600, fontFamily: "monospace", fontSize: 10 }}>{selectedNode.hostname}</span>
                </div>
              )}
              {selectedNode.cvss !== undefined && selectedNode.cvss > 0 && (
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>CVSS</span>
                  <span style={{ fontWeight: 700, color: selectedNode.cvss >= 9 ? "#e04040" : selectedNode.cvss >= 7 ? "#d07020" : "#d09020" }}>
                    {selectedNode.cvss}
                  </span>
                </div>
              )}
              {selectedNode.tactic && (
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>Tactique MITRE</span>
                  <span style={{ fontWeight: 600 }}>{selectedNode.tactic}</span>
                </div>
              )}
              {selectedNode.classification && (
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ color: "var(--tc-text-muted)" }}>Classification</span>
                  <span style={{ fontWeight: 600 }}>{selectedNode.classification}</span>
                </div>
              )}
            </div>

            {/* Relations */}
            {selectedNode.relations.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
                  Relations ({selectedNode.relations.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {selectedNode.relations.map((rel, i) => {
                    const targetData = nodesDataRef.current.get(rel.target);
                    const targetLabel = targetData?.data?.label || rel.target;
                    const targetType = targetData?.data?.nodeType || "?";
                    return (
                      <div key={i} style={{
                        display: "flex", alignItems: "center", gap: 6, padding: "4px 6px",
                        background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", fontSize: 10,
                      }}>
                        <span style={{ color: EDGE_COLORS[rel.type] || "var(--tc-text-muted)", fontWeight: 700, fontSize: 8, minWidth: 50 }}>
                          {rel.direction} {rel.type}
                        </span>
                        <span style={{ color: NODE_STYLES[targetType]?.color || "var(--tc-text)", fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {targetLabel.length > 20 ? targetLabel.slice(0, 18) + "…" : targetLabel}
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
          {stats.nodes} noeuds · {stats.edges} relations — hover = détail, clic = panneau, molette = zoom
        </div>
      )}
    </div>
  );
}
