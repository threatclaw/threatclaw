"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";

// ── STIX colors ──
const NODE_COLORS: Record<string, string> = {
  ip: "#e04040", asset: "#3080d0", cve: "#d09020",
  technique: "#9060d0", actor: "#d06020", campaign: "#30a050",
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

const CRIT_SIZES: Record<string, number> = {
  critical: 36, high: 30, medium: 24, low: 20,
};

export default function GraphVisualization() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<any>(null);
  const [loading, setLoading] = useState(true);
  const [nodeCount, setNodeCount] = useState(0);
  const [linkCount, setLinkCount] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const loadAndRender = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      // Fetch graph data
      const [r1, r2] = await Promise.all([
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, asset.hostname, asset.id, asset.type, asset.criticality, a.method LIMIT 100" }),
          signal: AbortSignal.timeout(10000),
        }),
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) RETURN c.id, c.cvss, a.id, a.hostname LIMIT 50" }),
          signal: AbortSignal.timeout(10000),
        }),
      ]);

      const d1 = await r1.json(), d2 = await r2.json();
      const strip = (s: any) => typeof s === "string" ? s.replace(/"/g, "") : String(s || "");

      // Build nodes and edges
      const nodeMap = new Map<string, any>();
      const edges: any[] = [];

      for (const r of (d1.results || [])) {
        const ip = strip(r["ip.addr"]), aid = strip(r["asset.id"]);
        const ah = strip(r["asset.hostname"]) || aid;
        const crit = strip(r["asset.criticality"]) || "medium";

        if (ip && !nodeMap.has(ip)) {
          nodeMap.set(ip, {
            id: ip, type: "ip",
            data: { label: ip, type: "ip", criticality: "high" },
          });
        }
        if (aid && !nodeMap.has(aid)) {
          nodeMap.set(aid, {
            id: aid, type: "asset",
            data: { label: ah.length > 20 ? ah.slice(0, 18) + "…" : ah, type: "asset", criticality: crit, hostname: ah },
          });
        }
        if (ip && aid) {
          const lateral = ip.startsWith("192.168.") || ip.startsWith("10.");
          edges.push({
            id: `${ip}-${aid}-${lateral ? "L" : "A"}`,
            source: ip, target: aid,
            data: { label: lateral ? "LATERAL" : "ATTACKS", type: lateral ? "LATERAL" : "ATTACKS" },
          });
        }
      }

      for (const r of (d2.results || [])) {
        const cid = strip(r["c.id"]), cvss = parseFloat(r["c.cvss"]) || 0;
        const aid = strip(r["a.id"]), ah = strip(r["a.hostname"]);

        if (cid && !nodeMap.has(cid)) {
          nodeMap.set(cid, {
            id: cid, type: "cve",
            data: { label: cid, type: "cve", cvss: cvss.toFixed(1) },
          });
        }
        if (aid && !nodeMap.has(aid)) {
          nodeMap.set(aid, {
            id: aid, type: "asset",
            data: { label: ah || aid.slice(0, 12), type: "asset", criticality: "medium" },
          });
        }
        if (cid && aid) {
          edges.push({
            id: `${cid}-${aid}-AFF`,
            source: cid, target: aid,
            data: { label: "AFFECTS", type: "AFFECTS" },
          });
        }
      }

      // Deduplicate edges
      const seen = new Set<string>();
      const dedupEdges = edges.filter(e => { if (seen.has(e.id)) return false; seen.add(e.id); return true; });

      const nodes = Array.from(nodeMap.values());
      setNodeCount(nodes.length);
      setLinkCount(dedupEdges.length);

      if (nodes.length === 0) { setLoading(false); return; }

      // ── Render with G6 ──
      const { Graph } = await import("@antv/g6");

      // Destroy previous instance
      if (graphRef.current) {
        try { graphRef.current.destroy(); } catch {}
        graphRef.current = null;
      }

      const container = containerRef.current;
      if (!container) return;

      // Clear container
      const graphDiv = container.querySelector("#g6-graph");
      if (graphDiv) graphDiv.innerHTML = "";

      const isLight = document.documentElement.getAttribute("data-theme") === "light";
      const width = container.clientWidth - 32;
      const height = 450;

      const graph = new Graph({
        container: "g6-graph",
        width,
        height,
        autoFit: "view",
        padding: [30, 30, 30, 30],
        data: { nodes, edges: dedupEdges },
        layout: {
          type: "dagre",
          rankdir: "LR",
          nodesep: 40,
          ranksep: 80,
        },
        node: {
          style: {
            size: (d: any) => CRIT_SIZES[d.data?.criticality] || 24,
            fill: (d: any) => NODE_COLORS[d.data?.type] || "#888",
            stroke: (d: any) => NODE_COLORS[d.data?.type] || "#888",
            lineWidth: 1,
            labelText: (d: any) => d.data?.label || d.id,
            labelFontSize: 10,
            labelFill: isLight ? "#333" : "#ccc",
            labelPlacement: "bottom",
            labelOffsetY: 4,
          },
          state: {
            active: {
              stroke: "#fff",
              lineWidth: 2,
              shadowBlur: 10,
              shadowColor: "rgba(255,255,255,0.3)",
            },
            inactive: {
              opacity: 0.3,
            },
          },
        },
        edge: {
          type: "line",
          style: {
            stroke: (d: any) => EDGE_COLORS[d.data?.type] || "rgba(150,150,150,0.4)",
            lineWidth: 2,
            endArrow: true,
            endArrowSize: 8,
            labelText: (d: any) => d.data?.label || "",
            labelFontSize: 9,
            labelFill: isLight ? "#666" : "#999",
            labelBackground: true,
            labelBackgroundFill: isLight ? "rgba(255,255,255,0.8)" : "rgba(0,0,0,0.6)",
            labelBackgroundRadius: 3,
            labelPadding: [2, 4, 2, 4],
          },
          state: {
            active: {
              lineWidth: 3,
            },
            inactive: {
              opacity: 0.15,
            },
          },
        },
        behaviors: [
          "drag-canvas",
          "zoom-canvas",
          "drag-element",
          {
            type: "hover-activate",
            degree: 1,
            state: "active",
            inactiveState: "inactive",
          },
        ],
        plugins: [
          {
            type: "tooltip",
            getContent: (_: any, items: any[]) => {
              if (!items || items.length === 0) return "";
              const item = items[0];
              const d = item.data || {};
              let html = `<div style="font-weight:700;font-size:13px;color:${NODE_COLORS[d.type] || "#888"};margin-bottom:4px">${d.label || item.id}</div>`;
              html += `<div style="font-size:9px;text-transform:uppercase;color:#888;margin-bottom:6px">${d.type || "node"}</div>`;
              if (d.criticality) html += `<div style="font-size:10px">Criticité: <b>${d.criticality}</b></div>`;
              if (d.hostname) html += `<div style="font-size:10px">Hostname: <b>${d.hostname}</b></div>`;
              if (d.cvss) html += `<div style="font-size:10px">CVSS: <b>${d.cvss}</b></div>`;
              return html;
            },
          },
          {
            type: "minimap",
            size: [120, 80],
          },
        ],
      });

      await graph.render();
      graphRef.current = graph;

    } catch (e: any) {
      setError(e.message || "Erreur de chargement");
    }

    setLoading(false);
  }, []);

  useEffect(() => {
    loadAndRender();
    return () => {
      if (graphRef.current) { try { graphRef.current.destroy(); } catch {} }
    };
  }, [loadAndRender]);

  return (
    <div ref={containerRef} style={{
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-md)", padding: "16px", position: "relative",
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Graphe d&apos;attaque
        </span>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>
          Chargement du graphe...
        </div>
      )}

      {error && (
        <div style={{ textAlign: "center", padding: "40px 0", color: "var(--tc-red)", fontSize: 12 }}>
          {error}
        </div>
      )}

      {!loading && nodeCount === 0 && !error && (
        <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>
          Aucune donnée. Lancez un test ou activez des connecteurs.
        </div>
      )}

      {/* G6 renders here */}
      <div id="g6-graph" style={{ width: "100%", minHeight: 450 }} />

      {nodeCount > 0 && (
        <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 6, textAlign: "center" }}>
          {nodeCount} noeuds · {linkCount} relations — glisser pour déplacer, molette pour zoomer, hover pour détails
        </div>
      )}
    </div>
  );
}
