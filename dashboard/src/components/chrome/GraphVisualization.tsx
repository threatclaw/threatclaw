"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";
import { X, Maximize2, Minimize2, Eye, EyeOff, ExternalLink } from "lucide-react";
import { t as tr } from "@/lib/i18n";
import { useLocale } from "@/lib/useLocale";

// ── SVG icon paths (24x24 viewBox) ──
const SVG_ICONS: Record<string, string> = {
  ip: "M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 2c1.9 2.3 3.2 5 3.4 8h-6.8c.2-3 1.5-5.7 3.4-8zm-4.8 8H3.1c.5-3 2.4-5.5 5-7-1.4 1.8-2.4 4.3-2.9 7zM5 5l14 14M19 5L5 19",
  server: "M4 4h16v4H4V4zm0 6h16v4H4v-4zm0 6h16v4H4v-4zm13-11h1v1h-1V5zm0 6h1v1h-1v-1zm0 6h1v1h-1v-1z",
  database: "M12 3C7.6 3 4 4.3 4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6c0-1.7-3.6-3-8-3zm0 2c3.3 0 6 .9 6 2s-2.7 2-6 2-6-.9-6-2 2.7-2 6-2zM4 10c0 1.1 2.7 2 6 2s6-.9 6-2M4 14c0 1.1 2.7 2 6 2s6-.9 6-2",
  workstation: "M5 4h14v10H5V4zm3 12h8v2H8v-2zm4 2v2",
  website: "M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 2c1.9 2.3 3.2 5 3.4 8h-6.8c.2-3 1.5-5.7 3.4-8zM2 12h20M12 2c4.4 0 8 4.5 8 10s-3.6 10-8 10",
  cve: "M12 2L2 22h20L12 2zm0 6v6m0 3v1",
  technique: "M12 2l8 4.5v7L12 18l-8-4.5v-7L12 2zm0 5v4m-3-2h6",
  actor: "M12 4a4 4 0 100 8 4 4 0 000-8zM6 20c0-3.3 2.7-6 6-6s6 2.7 6 6",
  campaign: "M5 3v18l7-4 7 4V3H5z",
  network: "M4 15h4v4H4v-4zm12 0h4v4h-4v-4zm-6-8h4v4h-4V7zM6 15V11h2m8 4V11h2M12 11V7",
  printer: "M6 3h12v5H6V3zm-2 5h16v8H4v-8zm2 6h12v4H6v-4z",
  iot: "M8 4h8v16H8V4zm-2 3h2v10H6V7zm10 0h2v10h-2V7zm-6-5h4v2h-4V2zm0 18h4v2h-4v-2z",
  camera: "M2 7h4l2-3h8l2 3h4v12H2V7zm10 2a4 4 0 100 8 4 4 0 000-8z",
  unknown: "M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm0 5a3 3 0 011 5.8V14h-2v-1.2A3 3 0 0112 7zm0 10a1.5 1.5 0 100-3 1.5 1.5 0 000 3z",
};

const NODE_ICON_MAP: Record<string, string> = {
  ip: "ip", asset: "server", cve: "cve", technique: "technique", actor: "actor", campaign: "campaign",
  server: "server", web: "website", db: "database", mail: "server", dns: "network", ad: "server",
  workstation: "workstation", desktop: "workstation", laptop: "workstation",
  website: "website", network: "network", firewall: "network",
  printer: "printer", iot: "iot", camera: "camera", ot: "iot", unknown: "unknown",
};

const NODE_COLORS: Record<string, string> = {
  ip: "#e04040", asset: "#3080d0", cve: "#d09020", technique: "#9060d0", actor: "#d06020", campaign: "#30a050",
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020", USES: "#9060d0", PART_OF: "#30a050",
};

const NODE_SHAPES: Record<string, string> = {
  ip: "ellipse", asset: "round-rectangle", cve: "round-triangle", technique: "diamond", actor: "ellipse", campaign: "round-rectangle",
};

function makeNodeSvg(nodeType: string, subcategory: string, color: string, size: number): string {
  const iconKey = NODE_ICON_MAP[subcategory] || NODE_ICON_MAP[nodeType] || "unknown";
  const iconPath = SVG_ICONS[iconKey] || SVG_ICONS.unknown;
  const half = size / 2;
  const iconSize = size * 0.45;
  const iconOffset = (size - iconSize) / 2;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <path d="${iconPath}" fill="none" stroke="white" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"
      transform="translate(${iconOffset},${iconOffset}) scale(${iconSize / 24})"/>
  </svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}

interface NodeDetail {
  id: string; label: string; nodeType: string;
  criticality?: string; hostname?: string; cvss?: number;
  tactic?: string; classification?: string;
  relations: { target: string; targetLabel: string; targetType: string; type: string; direction: string }[];
}

// ═══ MINI CARD (for Intelligence page) ═══
export function GraphCard({ onOpen }: { onOpen: () => void }) {
  const locale = useLocale();
  const [stats, setStats] = useState({ nodes: 0, edges: 0, ips: 0 });

  useEffect(() => {
    fetch("/api/tc/graph/query", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cypher: "MATCH (n) RETURN labels(n) AS type, count(*) AS total" }),
    }).then(r => r.json()).then(d => {
      let nodes = 0, ips = 0;
      for (const r of (d.results || [])) {
        const t = JSON.parse(r.type || "[]")[0] || "";
        const c = parseInt(r.total) || 0;
        nodes += c;
        if (t === "IP") ips = c;
      }
      setStats({ nodes, edges: 0, ips });
    }).catch(() => {});
  }, []);

  return (
    <div style={{
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-md)", padding: "16px", cursor: "pointer",
      transition: "border-color 0.2s",
    }} onClick={onOpen}
       onMouseEnter={e => (e.currentTarget.style.borderColor = "var(--tc-red)")}
       onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--tc-border)")}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("attackGraph", locale)}</span>
        <ExternalLink size={12} color="var(--tc-text-muted)" />
      </div>
      <div style={{ display: "flex", gap: 16, fontSize: 10, color: "var(--tc-text-muted)" }}>
        <span><b style={{ color: "var(--tc-text)", fontSize: 16 }}>{stats.nodes}</b> {tr("nodes", locale)}</span>
        <span><b style={{ color: "#e04040", fontSize: 16 }}>{stats.ips}</b> IPs</span>
      </div>
      <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 8, fontStyle: "italic" }}>
        {tr("clickToInvestigate", locale)}
      </div>
    </div>
  );
}

// ═══ FULL MODAL GRAPH ═══
export function GraphModal({ onClose }: { onClose: () => void }) {
  const locale = useLocale();
  const cyRef = useRef<any>(null);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });
  const [error, setError] = useState<string | null>(null);
  const [activeTypes, setActiveTypes] = useState<Set<string>>(new Set());
  const [selectedNode, setSelectedNode] = useState<NodeDetail | null>(null);
  const [simplified, setSimplified] = useState(true);
  const nodesDataRef = useRef<Map<string, any>>(new Map());
  const edgesDataRef = useRef<any[]>([]);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { if (selectedNode) setSelectedNode(null); else onClose(); }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedNode, onClose]);

  const loadAndRender = useCallback(async () => {
    setLoading(true); setError(null);

    try {
      const [r1, r2, r3] = await Promise.all([
        fetch("/api/tc/graph/query", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, ip.classification, asset.hostname, asset.id, asset.type, asset.criticality, a.method LIMIT 100" }),
          signal: AbortSignal.timeout(10000) }),
        fetch("/api/tc/graph/query", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) RETURN c.id, c.cvss, a.id, a.hostname LIMIT 50" }),
          signal: AbortSignal.timeout(10000) }),
        fetch("/api/tc/graph/query", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (t:Technique) RETURN t.mitre_id, t.name, t.tactic LIMIT 30" }),
          signal: AbortSignal.timeout(10000) }),
      ]);

      const d1 = await r1.json(), d2 = await r2.json(), d3 = await r3.json();
      const nodeMap = new Map<string, any>();
      const edges: any[] = [];
      const types = new Set<string>();
      const relCount = new Map<string, number>();
      const inc = (id: string) => relCount.set(id, (relCount.get(id) || 0) + 1);
      const isInternal = (ip: string) => ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.");

      for (const r of (d1.results || [])) {
        const ip = r["ip.addr"] || "", aid = r["asset.id"] || "";
        const ah = r["asset.hostname"] || aid, crit = r["asset.criticality"] || "medium";
        const assetType = r["asset.type"] || "server";

        // Internal IPs are assets, not threat IPs
        if (ip && !nodeMap.has(ip)) {
          if (isInternal(ip)) {
            types.add("asset");
            nodeMap.set(ip, { id: ip, label: ip, nodeType: "asset", subcategory: "network", criticality: "medium" });
          } else {
            types.add("ip");
            nodeMap.set(ip, { id: ip, label: ip, nodeType: "ip", subcategory: "ip", classification: r["ip.classification"] || "suspicious" });
          }
        }
        if (aid && !nodeMap.has(aid)) {
          types.add("asset");
          nodeMap.set(aid, { id: aid, label: ah.length > 18 ? ah.slice(0, 16) + "…" : ah, nodeType: "asset", subcategory: assetType, criticality: crit, hostname: ah });
        }
        if (ip && aid) {
          const lateral = isInternal(ip);
          const eid = `${ip}>${aid}>${lateral ? "L" : "A"}`;
          if (!edges.find(e => e.id === eid)) { edges.push({ id: eid, source: ip, target: aid, edgeType: lateral ? "LATERAL" : "ATTACKS" }); inc(ip); inc(aid); }
        }
      }

      for (const r of (d2.results || [])) {
        const cid = r["c.id"] || "", cvss = parseFloat(r["c.cvss"]) || 0, aid = r["a.id"] || "", ah = r["a.hostname"] || "";
        if (cid && !nodeMap.has(cid)) { types.add("cve"); nodeMap.set(cid, { id: cid, label: cid, nodeType: "cve", subcategory: "cve", cvss }); }
        if (aid && !nodeMap.has(aid)) { types.add("asset"); nodeMap.set(aid, { id: aid, label: ah || aid.slice(0, 12), nodeType: "asset", subcategory: "server" }); }
        if (cid && aid) { const eid = `${cid}>${aid}>AFF`; if (!edges.find(e => e.id === eid)) { edges.push({ id: eid, source: cid, target: aid, edgeType: "AFFECTS" }); inc(cid); inc(aid); } }
      }

      if (!simplified) {
        const attacked = new Set(edges.filter(e => e.edgeType === "ATTACKS" || e.edgeType === "LATERAL").map(e => e.target));
        for (const r of (d3.results || [])) {
          const tid = r["t.mitre_id"] || "", tname = r["t.name"] || "";
          if (tid && !nodeMap.has(tid)) {
            types.add("technique");
            nodeMap.set(tid, { id: tid, label: tname.length > 14 ? tname.slice(0, 12) + "…" : tname || tid, nodeType: "technique", subcategory: "technique", tactic: r["t.tactic"] || "", fullName: tname });
            const targets = Array.from(attacked);
            if (targets.length > 0) { const t = targets[Math.floor(Math.random() * targets.length)]; edges.push({ id: `${tid}>${t}>USES`, source: tid, target: t, edgeType: "USES" }); inc(tid); inc(t); }
          }
        }
      }

      nodesDataRef.current = nodeMap; edgesDataRef.current = edges;
      setStats({ nodes: nodeMap.size, edges: edges.length }); setActiveTypes(types);
      if (nodeMap.size === 0) { setLoading(false); return; }
      if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }

      const cytoscape = (await import("cytoscape")).default;
      const isLight = document.documentElement.getAttribute("data-theme") === "light";

      const cyNodes = Array.from(nodeMap.values()).map(n => ({
        data: {
          id: n.id, label: n.label, nodeType: n.nodeType, subcategory: n.subcategory || n.nodeType,
          criticality: n.criticality || "medium", hostname: n.hostname, cvss: n.cvss, tactic: n.tactic,
          classification: n.classification,
          size: 30 + (relCount.get(n.id) || 0) * 6 + (n.criticality === "critical" ? 14 : n.criticality === "high" ? 8 : 0),
          bgImg: makeNodeSvg(n.nodeType, n.subcategory || n.nodeType, NODE_COLORS[n.nodeType] || "#888", 48),
        },
      }));
      const cyEdges = edges.map(e => ({ data: { id: e.id, source: e.source, target: e.target, edgeType: e.edgeType, label: e.edgeType } }));

      const el = document.getElementById("cy-modal");
      if (!el) return;

      const cy = cytoscape({
        container: el,
        elements: [...cyNodes, ...cyEdges],
        style: [
          { selector: "node", style: {
            "label": "data(label)", "text-valign": "bottom", "text-halign": "center", "text-margin-y": 8,
            "font-size": 11, "font-weight": "bold", "font-family": "Inter, sans-serif",
            "color": isLight ? "#111" : "#eee", "text-outline-width": 2, "text-outline-color": isLight ? "rgba(255,255,255,0.9)" : "rgba(0,0,0,0.8)",
            "width": "data(size)", "height": "data(size)", "border-width": 2.5, "background-opacity": 0.2,
            "background-image": "data(bgImg)", "background-fit": "contain", "background-clip": "none",
            "background-width": "60%", "background-height": "60%",
          } as any },
          ...Object.entries(NODE_COLORS).map(([type, color]) => ({
            selector: `node[nodeType="${type}"]`, style: {
              "background-color": color, "border-color": color, "shape": NODE_SHAPES[type] || "ellipse",
              "shadow-blur": 12, "shadow-color": color, "shadow-opacity": 0.3,
            } as any,
          })),
          // Critical glow
          { selector: 'node[criticality="critical"]', style: { "shadow-blur": 20, "shadow-opacity": 0.5, "border-width": 3 } as any },
          // Threat actor dashed border
          { selector: 'node[nodeType="actor"]', style: { "border-style": "dashed", "border-width": 2 } as any },
          // Edges
          { selector: "edge", style: {
            "width": 2, "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 1.2,
            "label": "data(label)", "font-size": 9, "font-weight": "bold", "font-family": "Inter, sans-serif",
            "color": isLight ? "#333" : "#bbb", "text-outline-width": 2, "text-outline-color": isLight ? "rgba(255,255,255,0.9)" : "rgba(0,0,0,0.8)",
            "text-rotation": "autorotate", "text-margin-y": -10,
          } as any },
          ...Object.entries(EDGE_COLORS).map(([type, color]) => ({
            selector: `edge[edgeType="${type}"]`, style: { "line-color": color, "target-arrow-color": color } as any,
          })),
          // Lateral dashed
          { selector: 'edge[edgeType="LATERAL"]', style: { "line-style": "dashed", "line-dash-pattern": [6, 3] } as any },
        ],
        layout: { name: "breadthfirst", directed: true, padding: 50, spacingFactor: 1.5, avoidOverlap: true } as any,
        minZoom: 0.2, maxZoom: 4, wheelSensitivity: 0.3,
      });

      cy.on("tap", "node", (evt: any) => {
        const d = evt.target.data();
        const rels = edges.filter(e => e.source === d.id || e.target === d.id).map(e => {
          const tid = e.source === d.id ? e.target : e.source;
          const td = nodeMap.get(tid);
          return { target: tid, targetLabel: td?.label || tid, targetType: td?.nodeType || "?", type: e.edgeType, direction: e.source === d.id ? "→" : "←" };
        });
        setSelectedNode({ id: d.id, label: d.label, nodeType: d.nodeType, criticality: d.criticality, hostname: d.hostname, cvss: d.cvss, tactic: d.tactic, classification: d.classification, relations: rels });
      });
      cy.on("tap", (evt: any) => { if (evt.target === cy) setSelectedNode(null); });
      cy.fit(undefined, 50);
      cyRef.current = cy;
    } catch (e: any) { setError(e.message || tr("serverError", locale)); }
    setLoading(false);
  }, [simplified]);

  useEffect(() => { loadAndRender(); return () => { if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; } }; }, [loadAndRender]);

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 9999, background: "var(--tc-bg)", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 20px", borderBottom: "1px solid var(--tc-border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 15, fontWeight: 800, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>{tr("investigation", locale)}</span>
          <button onClick={() => setSimplified(!simplified)} style={{ background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", cursor: "pointer", color: "var(--tc-text-muted)", padding: "3px 8px", display: "flex", alignItems: "center", gap: 4, fontSize: 9, fontFamily: "inherit" }}>
            {simplified ? <Eye size={11} /> : <EyeOff size={11} />} {simplified ? tr("graphSimple", locale) : tr("graphFull", locale)}
          </button>
          <span style={{ fontSize: 10, color: "var(--tc-text-muted)" }}>{stats.nodes} {tr("nodes", locale)} · {stats.edges} {tr("relations", locale)}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", gap: 8, fontSize: 9 }}>
            {Object.entries(NODE_COLORS).filter(([t]) => activeTypes.has(t)).map(([type, color]) => (
              <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
                <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} /> {type}
              </span>
            ))}
          </div>
          <button onClick={onClose} style={{ background: "none", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", cursor: "pointer", color: "var(--tc-text-muted)", padding: "4px 8px", display: "flex", alignItems: "center", gap: 4, fontSize: 10, fontFamily: "inherit" }}>
            <X size={12} /> {tr("close", locale)}
          </button>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {loading && <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--tc-text-muted)" }}>{tr("loading", locale)}</div>}
        {error && <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "#d03020" }}>{error}</div>}

        <div id="cy-modal" style={{ flex: 1, minHeight: 0 }} />

        {selectedNode && (
          <div style={{ width: 280, borderLeft: "1px solid var(--tc-border)", padding: "16px 14px", overflowY: "auto" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: NODE_COLORS[selectedNode.nodeType] || "#888", textTransform: "uppercase" }}>{selectedNode.nodeType}</span>
              <button onClick={() => setSelectedNode(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--tc-text-muted)" }}><X size={14} /></button>
            </div>
            <div style={{ fontSize: 17, fontWeight: 800, color: "var(--tc-text)", marginBottom: 14, wordBreak: "break-all" }}>{selectedNode.label}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 11 }}>
              {selectedNode.criticality && <Row label="Criticité" value={selectedNode.criticality.toUpperCase()} color={selectedNode.criticality === "critical" ? "#e04040" : selectedNode.criticality === "high" ? "#d07020" : undefined} />}
              {selectedNode.hostname && selectedNode.hostname !== selectedNode.label && <Row label="Hostname" value={selectedNode.hostname} mono />}
              {selectedNode.cvss !== undefined && selectedNode.cvss > 0 && <Row label="CVSS" value={String(selectedNode.cvss)} color={selectedNode.cvss >= 9 ? "#e04040" : "#d09020"} />}
              {selectedNode.tactic && <Row label="Tactique" value={selectedNode.tactic} />}
              {selectedNode.classification && <Row label="Classification" value={selectedNode.classification} />}
            </div>
            {selectedNode.relations.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <div style={{ fontSize: 9, fontWeight: 700, color: "var(--tc-text-muted)", textTransform: "uppercase", marginBottom: 6 }}>Relations ({selectedNode.relations.length})</div>
                {selectedNode.relations.map((rel, i) => (
                  <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 6px", background: "var(--tc-input)", borderRadius: "var(--tc-radius-sm)", fontSize: 10, marginBottom: 3 }}>
                    <span style={{ color: EDGE_COLORS[rel.type] || "var(--tc-text-muted)", fontWeight: 700, fontSize: 8, minWidth: 55 }}>{rel.direction} {rel.type}</span>
                    <span style={{ color: NODE_COLORS[rel.targetType] || "var(--tc-text)", fontWeight: 600, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{rel.targetLabel.slice(0, 18)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ═══ DEFAULT EXPORT (backward compat) ═══
export default function GraphVisualization() {
  const [modalOpen, setModalOpen] = useState(false);
  return (
    <>
      <GraphCard onOpen={() => setModalOpen(true)} />
      {modalOpen && <GraphModal onClose={() => setModalOpen(false)} />}
    </>
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
