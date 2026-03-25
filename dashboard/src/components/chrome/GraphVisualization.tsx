"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";

const NODE_STYLES: Record<string, { color: string; shape: string; label: string }> = {
  ip:        { color: "#e04040", shape: "diamond",  label: "IP" },
  asset:     { color: "#3080d0", shape: "rect",     label: "Asset" },
  cve:       { color: "#d09020", shape: "triangle", label: "CVE" },
  technique: { color: "#9060d0", shape: "diamond",  label: "Technique" },
  actor:     { color: "#d06020", shape: "hexagon",  label: "Acteur" },
  campaign:  { color: "#30a050", shape: "rect",     label: "Campagne" },
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

export default function GraphVisualization() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });
  const [error, setError] = useState<string | null>(null);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());

  const loadAndRender = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Query ALL relationships in the graph
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

      // IP → Asset attacks
      for (const r of (d1.results || [])) {
        const ip = r["ip.addr"] || "";
        const aid = r["asset.id"] || "";
        const ah = r["asset.hostname"] || aid;
        const crit = r["asset.criticality"] || "medium";

        if (ip && !nodeMap.has(ip)) {
          types.add("ip");
          nodeMap.set(ip, { id: ip, data: { label: ip, nodeType: "ip" } });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          const label = ah.length > 18 ? ah.slice(0, 16) + "…" : ah;
          nodeMap.set(aid, { id: aid, data: { label, nodeType: "asset", criticality: crit, hostname: ah } });
        }
        if (ip && aid) {
          const lateral = ip.startsWith("192.168.") || ip.startsWith("10.");
          const eid = `${ip}>${aid}>${lateral ? "L" : "A"}`;
          if (!edgeList.find(e => e.id === eid)) {
            edgeList.push({ id: eid, source: ip, target: aid, data: { edgeType: lateral ? "LATERAL" : "ATTACKS" } });
          }
        }
      }

      // CVE → Asset
      for (const r of (d2.results || [])) {
        const cid = r["c.id"] || "";
        const cvss = parseFloat(r["c.cvss"]) || 0;
        const aid = r["a.id"] || "";
        const ah = r["a.hostname"] || "";

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
          }
        }
      }

      // Techniques (standalone nodes — connected to assets via alerts in the future)
      for (const r of (d3.results || [])) {
        const tid = r["t.mitre_id"] || "";
        const tname = r["t.name"] || "";
        if (tid && !nodeMap.has(tid)) {
          types.add("technique");
          const label = tname.length > 16 ? tname.slice(0, 14) + "…" : tname;
          nodeMap.set(tid, { id: tid, data: { label: label || tid, nodeType: "technique", tactic: r["t.tactic"] || "" } });
        }
      }

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
        height: 450,
        autoFit: "view",
        padding: 40,
        data: { nodes, edges: edgeList },
        layout: {
          type: "dagre",
          rankdir: "LR",
          nodesep: 50,
          ranksep: 100,
        },
        node: {
          type: (d: any) => {
            const nt = d.data?.nodeType || "asset";
            const shape = NODE_STYLES[nt]?.shape || "circle";
            return shape;
          },
          style: {
            size: (d: any) => {
              const nt = d.data?.nodeType;
              if (nt === "technique") return 18;
              if (nt === "cve") return 22;
              const crit = d.data?.criticality;
              if (crit === "critical") return 36;
              if (crit === "high") return 30;
              return 26;
            },
            fill: (d: any) => NODE_STYLES[d.data?.nodeType]?.color || "#888",
            stroke: (d: any) => {
              const c = NODE_STYLES[d.data?.nodeType]?.color || "#888";
              return c;
            },
            lineWidth: 2,
            radius: 6,
            labelText: (d: any) => d.data?.label || d.id,
            labelFontSize: 10,
            labelFill: isLight ? "#333" : "#ccc",
            labelPlacement: "bottom",
            labelOffsetY: 8,
            labelFontFamily: "Inter, sans-serif",
          },
        },
        edge: {
          type: "line",
          style: {
            stroke: (d: any) => EDGE_COLORS[d.data?.edgeType] || "rgba(150,150,150,0.4)",
            lineWidth: 2,
            endArrow: true,
            endArrowSize: 8,
            labelText: (d: any) => d.data?.edgeType || "",
            labelFontSize: 8,
            labelFill: isLight ? "#555" : "#aaa",
            labelFontFamily: "Inter, sans-serif",
          },
        },
        behaviors: ["drag-canvas", "zoom-canvas", "drag-element"],
      });

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

  return (
    <div ref={containerRef} style={{
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-md)", padding: "16px", position: "relative",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Graphe d&apos;attaque
        </span>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_STYLES)
            .filter(([type]) => activeTypes.has(type))
            .map(([type, s]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: s.shape === "diamond" ? "1px" : s.shape === "rect" ? "2px" : "50%", background: s.color, display: "inline-block", transform: s.shape === "diamond" ? "rotate(45deg)" : "none" }} />
              {s.label}
            </span>
          ))}
        </div>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Chargement du graphe...</div>}
      {error && <div style={{ textAlign: "center", padding: "40px 0", color: "#d03020", fontSize: 11 }}>{error}</div>}
      {!loading && stats.nodes === 0 && !error && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Aucune donnée. Lancez un test.</div>}

      <div id="g6-container" style={{ width: "100%", minHeight: loading || stats.nodes === 0 ? 0 : 450 }} />

      {stats.nodes > 0 && !loading && (
        <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 6, textAlign: "center" }}>
          {stats.nodes} noeuds · {stats.edges} relations — glisser = déplacer, molette = zoom
        </div>
      )}
    </div>
  );
}
