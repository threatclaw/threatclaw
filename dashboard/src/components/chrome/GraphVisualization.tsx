"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";
import { X, Maximize2, Minimize2, Eye, EyeOff } from "lucide-react";

const NODE_COLORS: Record<string, string> = {
  ip: "#e04040", asset: "#3080d0", cve: "#d09020",
  technique: "#9060d0", actor: "#d06020", campaign: "#30a050",
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

const NODE_SHAPES: Record<string, string> = {
  ip: "diamond", asset: "round-rectangle", cve: "triangle",
  technique: "diamond", actor: "hexagon", campaign: "round-rectangle",
};

interface NodeDetail {
  id: string; label: string; nodeType: string;
  criticality?: string; hostname?: string; cvss?: number;
  tactic?: string; classification?: string;
  relations: { target: string; type: string; direction: string }[];
}

export default function GraphVisualization() {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null);
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

    try {
      const [r1, r2, r3] = await Promise.all([
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
      ]);

      const d1 = await r1.json(), d2 = await r2.json(), d3 = await r3.json();
      const nodeMap = new Map<string, any>();
      const edges: any[] = [];
      const types = new Set<string>();
      const relCount = new Map<string, number>();
      const inc = (id: string) => relCount.set(id, (relCount.get(id) || 0) + 1);

      for (const r of (d1.results || [])) {
        const ip = r["ip.addr"] || "", aid = r["asset.id"] || "";
        const ah = r["asset.hostname"] || aid, crit = r["asset.criticality"] || "medium";
        if (ip && !nodeMap.has(ip)) {
          types.add("ip"); nodeMap.set(ip, { id: ip, label: ip, nodeType: "ip", classification: r["ip.classification"] || "" });
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset"); nodeMap.set(aid, { id: aid, label: ah.length > 18 ? ah.slice(0, 16) + "…" : ah, nodeType: "asset", criticality: crit, hostname: ah });
        }
        if (ip && aid) {
          const lateral = ip.startsWith("192.168.") || ip.startsWith("10.");
          const eid = `${ip}>${aid}>${lateral ? "L" : "A"}`;
          if (!edges.find(e => e.id === eid)) { edges.push({ id: eid, source: ip, target: aid, edgeType: lateral ? "LATERAL" : "ATTACKS" }); inc(ip); inc(aid); }
        }
      }

      for (const r of (d2.results || [])) {
        const cid = r["c.id"] || "", cvss = parseFloat(r["c.cvss"]) || 0, aid = r["a.id"] || "", ah = r["a.hostname"] || "";
        if (cid && !nodeMap.has(cid)) { types.add("cve"); nodeMap.set(cid, { id: cid, label: cid, nodeType: "cve", cvss }); }
        if (aid && !nodeMap.has(aid)) { types.add("asset"); nodeMap.set(aid, { id: aid, label: ah || aid.slice(0, 12), nodeType: "asset" }); }
        if (cid && aid) { const eid = `${cid}>${aid}>AFF`; if (!edges.find(e => e.id === eid)) { edges.push({ id: eid, source: cid, target: aid, edgeType: "AFFECTS" }); inc(cid); inc(aid); } }
      }

      if (!simplified) {
        const attacked = new Set(edges.filter(e => e.edgeType === "ATTACKS" || e.edgeType === "LATERAL").map(e => e.target));
        for (const r of (d3.results || [])) {
          const tid = r["t.mitre_id"] || "", tname = r["t.name"] || "";
          if (tid && !nodeMap.has(tid)) {
            types.add("technique");
            nodeMap.set(tid, { id: tid, label: tname.length > 14 ? tname.slice(0, 12) + "…" : tname || tid, nodeType: "technique", tactic: r["t.tactic"] || "", fullName: tname });
            const targets = Array.from(attacked);
            if (targets.length > 0) { const t = targets[Math.floor(Math.random() * targets.length)]; edges.push({ id: `${tid}>${t}>USES`, source: tid, target: t, edgeType: "USES" }); inc(tid); inc(t); }
          }
        }
      }

      nodesDataRef.current = nodeMap;
      edgesDataRef.current = edges;
      setStats({ nodes: nodeMap.size, edges: edges.length });
      setActiveTypes(types);

      if (nodeMap.size === 0) { setLoading(false); return; }

      // Destroy previous cytoscape instance
      if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }

      const cytoscape = (await import("cytoscape")).default;
      const isLight = document.documentElement.getAttribute("data-theme") === "light";

      const cyNodes = Array.from(nodeMap.values()).map(n => ({
        data: {
          id: n.id, label: n.label, nodeType: n.nodeType,
          criticality: n.criticality || "medium", hostname: n.hostname,
          cvss: n.cvss, tactic: n.tactic, classification: n.classification,
          size: 30 + (relCount.get(n.id) || 0) * 6 + (n.criticality === "critical" ? 14 : n.criticality === "high" ? 8 : 0),
        },
      }));

      const cyEdges = edges.map(e => ({
        data: { id: e.id, source: e.source, target: e.target, edgeType: e.edgeType, label: e.edgeType },
      }));

      const el = document.getElementById("cy-container");
      if (!el) { setLoading(false); return; }

      const cy = cytoscape({
        container: el,
        elements: [...cyNodes, ...cyEdges],
        style: [
          {
            selector: "node",
            style: {
              "label": "data(label)",
              "text-valign": "bottom",
              "text-halign": "center",
              "text-margin-y": 6,
              "font-size": 11,
              "font-weight": "bold",
              "font-family": "Inter, sans-serif",
              "color": isLight ? "#111" : "#eee",
              "text-outline-width": 2,
              "text-outline-color": isLight ? "rgba(255,255,255,0.8)" : "rgba(0,0,0,0.7)",
              "width": "data(size)",
              "height": "data(size)",
              "border-width": 2.5,
              "background-opacity": 0.15,
            } as any,
          },
          // Node colors by type
          ...Object.entries(NODE_COLORS).map(([type, color]) => ({
            selector: `node[nodeType="${type}"]`,
            style: {
              "background-color": color,
              "border-color": color,
              "shape": NODE_SHAPES[type] || "ellipse",
            } as any,
          })),
          {
            selector: "edge",
            style: {
              "width": 2,
              "curve-style": "bezier",
              "target-arrow-shape": "triangle",
              "target-arrow-color": "data(edgeType)",
              "arrow-scale": 1.2,
              "label": "data(label)",
              "font-size": 9,
              "font-weight": "bold",
              "font-family": "Inter, sans-serif",
              "color": isLight ? "#333" : "#bbb",
              "text-outline-width": 2,
              "text-outline-color": isLight ? "rgba(255,255,255,0.8)" : "rgba(0,0,0,0.7)",
              "text-rotation": "autorotate",
              "text-margin-y": -8,
            } as any,
          },
          // Edge colors by type
          ...Object.entries(EDGE_COLORS).map(([type, color]) => ({
            selector: `edge[edgeType="${type}"]`,
            style: {
              "line-color": color,
              "target-arrow-color": color,
            } as any,
          })),
        ],
        layout: {
          name: "breadthfirst",
          directed: true,
          padding: 40,
          spacingFactor: 1.5,
          avoidOverlap: true,
        } as any,
        minZoom: 0.3,
        maxZoom: 3,
        wheelSensitivity: 0.3,
      });

      // Click handler
      cy.on("tap", "node", (evt: any) => {
        const node = evt.target;
        const d = node.data();
        const rels = edges
          .filter(e => e.source === d.id || e.target === d.id)
          .map(e => ({ target: e.source === d.id ? e.target : e.source, type: e.edgeType, direction: e.source === d.id ? "→" : "←" }));
        setSelectedNode({
          id: d.id, label: d.label, nodeType: d.nodeType,
          criticality: d.criticality, hostname: d.hostname, cvss: d.cvss,
          tactic: d.tactic, classification: d.classification, relations: rels,
        });
      });

      cy.on("tap", (evt: any) => {
        if (evt.target === cy) setSelectedNode(null);
      });

      cy.fit(undefined, 40);
      cyRef.current = cy;
    } catch (e: any) {
      console.error("Graph:", e);
      setError(e.message || "Erreur");
    }
    setLoading(false);
  }, [fullscreen, simplified]);

  useEffect(() => {
    loadAndRender();
    return () => { if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; } };
  }, [loadAndRender]);

  return (
    <div ref={containerRef} style={{
      padding: "2px", borderRadius: fullscreen ? 0 : "var(--tc-radius-md)",
      position: fullscreen ? "fixed" : "relative",
      backgroundColor: fullscreen ? "var(--tc-bg)" : "var(--tc-neu-outer)",
      boxShadow: fullscreen ? "none" : "inset 0 3px 8px rgba(0,0,0,0.45), inset 0 1px 3px rgba(0,0,0,0.35), 0 1px 0 rgba(255,255,255,0.12)",
      ...(fullscreen ? { top: 0, left: 0, right: 0, bottom: 0, zIndex: 9999 } : {}),
    }}>
    <div style={{
      borderRadius: fullscreen ? 0 : "calc(var(--tc-radius-md) - 2px)",
      padding: "16px",
      backgroundColor: fullscreen ? "transparent" : "var(--tc-neu-inner)",
      boxShadow: fullscreen ? "none" : "inset 0 4px 10px rgba(0,0,0,0.4), inset 0 2px 4px rgba(0,0,0,0.3)",
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Graphe d&apos;attaque
          </span>
          <button onClick={() => setSimplified(!simplified)} style={{
            background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 8px", display: "flex", alignItems: "center", gap: 4, fontSize: 9, fontFamily: "inherit",
          }}>
            {simplified ? <Eye size={11} /> : <EyeOff size={11} />}
            {simplified ? "Simple" : "Complet"}
          </button>
          <button onClick={() => setFullscreen(!fullscreen)} style={{
            background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)",
            cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 6px", display: "flex", alignItems: "center",
          }}>
            {fullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
          </button>
        </div>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_COLORS).filter(([t]) => activeTypes.has(t)).map(([type, color]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: NODE_SHAPES[type] === "diamond" ? 1 : NODE_SHAPES[type] === "round-rectangle" ? 2 : "50%", background: color, display: "inline-block", transform: NODE_SHAPES[type] === "diamond" ? "rotate(45deg)" : "none" }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Chargement...</div>}
      {error && <div style={{ textAlign: "center", padding: "40px 0", color: "#d03020", fontSize: 11 }}>{error}</div>}
      {!loading && stats.nodes === 0 && !error && <div style={{ textAlign: "center", padding: "80px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Aucune donnée. Lancez un test.</div>}

      <div style={{ display: "flex", gap: 0 }}>
        <div id="cy-container" style={{
          flex: 1, minHeight: fullscreen ? "calc(100vh - 80px)" : 450,
          background: "transparent",
        }} />

        {selectedNode && (
          <div style={{
            width: 260, flexShrink: 0, borderLeft: "1px solid var(--tc-border)",
            padding: "16px", overflowY: "auto", maxHeight: fullscreen ? "calc(100vh - 80px)" : 450,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: NODE_COLORS[selectedNode.nodeType] || "#888", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {selectedNode.nodeType}
              </span>
              <button onClick={() => setSelectedNode(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)", padding: 2 }}><X size={14} /></button>
            </div>
            <div style={{ fontSize: 16, fontWeight: 800, color: "var(--tc-text)", marginBottom: 12, wordBreak: "break-all" }}>{selectedNode.label}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 11 }}>
              {selectedNode.criticality && <Row label="Criticité" value={selectedNode.criticality.toUpperCase()} color={selectedNode.criticality === "critical" ? "#e04040" : selectedNode.criticality === "high" ? "#d07020" : undefined} />}
              {selectedNode.hostname && selectedNode.hostname !== selectedNode.label && <Row label="Hostname" value={selectedNode.hostname} mono />}
              {selectedNode.cvss !== undefined && selectedNode.cvss > 0 && <Row label="CVSS" value={String(selectedNode.cvss)} color={selectedNode.cvss >= 9 ? "#e04040" : "#d09020"} />}
              {selectedNode.tactic && <Row label="Tactique" value={selectedNode.tactic} />}
              {selectedNode.classification && <Row label="Type" value={selectedNode.classification} />}
            </div>
            {selectedNode.relations.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 6 }}>Relations ({selectedNode.relations.length})</div>
                {selectedNode.relations.map((rel, i) => {
                  const td = nodesDataRef.current.get(rel.target);
                  return (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 6px", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", fontSize: 10, marginBottom: 3 }}>
                      <span style={{ color: EDGE_COLORS[rel.type] || "var(--tc-text-muted)", fontWeight: 700, fontSize: 8, minWidth: 55 }}>{rel.direction} {rel.type}</span>
                      <span style={{ color: NODE_COLORS[td?.nodeType] || "var(--tc-text)", fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(td?.label || rel.target).slice(0, 18)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {stats.nodes > 0 && !loading && (
        <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 6, textAlign: "center" }}>
          {stats.nodes} noeuds · {stats.edges} relations — clic = détail · ESC = fermer · molette = zoom · glisser = déplacer
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
