"use client";

import React, { useRef, useEffect, useState, useCallback, useMemo } from "react";
import dynamic from "next/dynamic";

// Dynamic import — react-force-graph uses canvas, no SSR
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

// ── STIX color scheme ──
const NODE_COLORS: Record<string, string> = {
  ip: "#e04040", asset: "#3080d0", cve: "#d09020",
  technique: "#9060d0", actor: "#d06020", campaign: "#30a050",
};

const NODE_SIZES: Record<string, number> = {
  ip: 6, asset: 8, cve: 5, technique: 4, actor: 7, campaign: 6,
};

const EDGE_COLORS: Record<string, string> = {
  ATTACKS: "#e04040", AFFECTS: "#d09020", LATERAL: "#d06020",
  USES: "#9060d0", PART_OF: "#30a050",
};

interface GNode { id: string; label: string; type: string; val: number; color: string; extra?: Record<string, string | number>; }
interface GLink { source: string; target: string; label: string; color: string; }

export default function GraphVisualization() {
  const graphRef = useRef<any>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [graphData, setGraphData] = useState<{ nodes: GNode[]; links: GLink[] }>({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [hoverNode, setHoverNode] = useState<GNode | null>(null);
  const [dims, setDims] = useState({ w: 600, h: 400 });

  useEffect(() => {
    const update = () => { if (containerRef.current) setDims({ w: containerRef.current.clientWidth - 32, h: 400 }); };
    update(); window.addEventListener("resize", update); return () => window.removeEventListener("resize", update);
  }, []);

  const loadGraph = useCallback(async () => {
    setLoading(true);
    try {
      const [r1, r2] = await Promise.all([
        fetch("/api/tc/graph/query", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, asset.hostname, asset.id, asset.type, asset.criticality, a.method LIMIT 100" }),
          signal: AbortSignal.timeout(10000) }),
        fetch("/api/tc/graph/query", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) RETURN c.id, c.cvss, a.id, a.hostname LIMIT 50" }),
          signal: AbortSignal.timeout(10000) }),
      ]);
      const d1 = await r1.json(), d2 = await r2.json();
      const nm = new Map<string, GNode>(); const ll: GLink[] = [];
      const strip = (s: any) => typeof s === "string" ? s.replace(/"/g, "") : String(s || "");

      for (const r of (d1.results || [])) {
        const ip = strip(r["ip.addr"]), aid = strip(r["asset.id"]), ah = strip(r["asset.hostname"]) || aid;
        const crit = strip(r["asset.criticality"]) || "medium";
        if (ip && !nm.has(ip)) nm.set(ip, { id: ip, label: ip, type: "ip", val: NODE_SIZES.ip, color: NODE_COLORS.ip, extra: { type: "IP" } });
        if (aid && !nm.has(aid)) {
          const sz = crit === "critical" ? 12 : crit === "high" ? 10 : 8;
          nm.set(aid, { id: aid, label: ah.length > 20 ? ah.slice(0, 18) + "…" : ah, type: "asset", val: sz, color: NODE_COLORS.asset, extra: { criticality: crit, hostname: ah } });
        }
        if (ip && aid) {
          const lateral = ip.startsWith("192.168.") || ip.startsWith("10.");
          ll.push({ source: ip, target: aid, label: lateral ? "LATERAL" : "ATTACKS", color: lateral ? EDGE_COLORS.LATERAL : EDGE_COLORS.ATTACKS });
        }
      }
      for (const r of (d2.results || [])) {
        const cid = strip(r["c.id"]), cvss = parseFloat(r["c.cvss"]) || 0, aid = strip(r["a.id"]), ah = strip(r["a.hostname"]);
        if (cid && !nm.has(cid)) nm.set(cid, { id: cid, label: cid, type: "cve", val: Math.max(3, cvss), color: NODE_COLORS.cve, extra: { cvss: cvss.toFixed(1) } });
        if (aid && !nm.has(aid)) nm.set(aid, { id: aid, label: ah || aid.slice(0, 12), type: "asset", val: NODE_SIZES.asset, color: NODE_COLORS.asset });
        if (cid && aid) ll.push({ source: cid, target: aid, label: "AFFECTS", color: EDGE_COLORS.AFFECTS });
      }
      // Deduplicate links
      const seen = new Set<string>();
      const links = ll.filter(l => { const k = `${l.source}-${l.target}-${l.label}`; if (seen.has(k)) return false; seen.add(k); return true; });
      setGraphData({ nodes: Array.from(nm.values()), links });
    } catch (e) { console.error("Graph:", e); }
    setLoading(false);
  }, []);

  useEffect(() => { loadGraph(); }, [loadGraph]);

  // ── Custom renderers ──
  const paintNode = useCallback((node: any, ctx: CanvasRenderingContext2D, gs: number) => {
    const r = node.val || 5; const hov = hoverNode?.id === node.id;
    if (hov) { ctx.beginPath(); ctx.arc(node.x, node.y, r + 4, 0, Math.PI * 2); ctx.fillStyle = node.color + "40"; ctx.fill(); }
    ctx.beginPath(); ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    ctx.fillStyle = node.color; ctx.fill();
    ctx.strokeStyle = hov ? "#fff" : node.color + "60"; ctx.lineWidth = hov ? 2 : 0.5; ctx.stroke();
    if (gs > 0.6) {
      const light = document.documentElement.getAttribute("data-theme") === "light";
      ctx.fillStyle = light ? "rgba(0,0,0,0.7)" : "rgba(255,255,255,0.7)";
      ctx.font = `${Math.max(3, 10 / gs)}px Inter, sans-serif`; ctx.textAlign = "center";
      const lbl = (node.label || "").length > 16 ? node.label.slice(0, 14) + "…" : node.label;
      ctx.fillText(lbl, node.x, node.y + r + 10 / gs);
    }
  }, [hoverNode]);

  const paintLink = useCallback((link: any, ctx: CanvasRenderingContext2D, gs: number) => {
    const s = link.source, t = link.target; if (!s?.x || !t?.x) return;
    const dx = t.x - s.x, dy = t.y - s.y, dist = Math.sqrt(dx * dx + dy * dy) || 1;
    // Line
    ctx.beginPath(); ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y);
    ctx.strokeStyle = link.color || "rgba(150,150,150,0.3)"; ctx.lineWidth = 1.5 / gs; ctx.stroke();
    // Arrow
    const endR = t.val || 5; const al = 6 / gs; const angle = Math.atan2(dy, dx);
    const ax = t.x - (dx / dist) * (endR + 3), ay = t.y - (dy / dist) * (endR + 3);
    ctx.beginPath(); ctx.moveTo(ax, ay);
    ctx.lineTo(ax - al * Math.cos(angle - Math.PI / 6), ay - al * Math.sin(angle - Math.PI / 6));
    ctx.lineTo(ax - al * Math.cos(angle + Math.PI / 6), ay - al * Math.sin(angle + Math.PI / 6));
    ctx.closePath(); ctx.fillStyle = link.color || "rgba(150,150,150,0.5)"; ctx.fill();
    // Label on zoom
    if (gs > 1.2) {
      ctx.fillStyle = "rgba(150,150,150,0.5)"; ctx.font = `${Math.max(2, 8 / gs)}px Inter, sans-serif`; ctx.textAlign = "center";
      ctx.fillText(link.label || "", (s.x + t.x) / 2, (s.y + t.y) / 2 - 3 / gs);
    }
  }, []);

  // Tooltip
  const tooltip = useMemo(() => {
    if (!hoverNode) return null;
    const ex = hoverNode.extra || {};
    const rels = graphData.links.filter(l => {
      const sid = typeof l.source === "object" ? (l.source as any).id : l.source;
      const tid = typeof l.target === "object" ? (l.target as any).id : l.target;
      return sid === hoverNode.id || tid === hoverNode.id;
    });
    return (
      <div style={{ position: "absolute", top: 10, right: 10, zIndex: 10, background: "var(--tc-bg)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-sm)", padding: "10px 12px", fontSize: "10px", color: "var(--tc-text)", minWidth: 160, boxShadow: "0 4px 12px rgba(0,0,0,0.3)" }}>
        <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 4, color: hoverNode.color }}>{hoverNode.label}</div>
        <div style={{ color: "var(--tc-text-muted)", textTransform: "uppercase", fontSize: 8, letterSpacing: "0.05em", marginBottom: 6 }}>{hoverNode.type}</div>
        {Object.entries(ex).map(([k, v]) => (
          <div key={k} style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 2 }}>
            <span style={{ color: "var(--tc-text-muted)" }}>{k}</span>
            <span style={{ fontWeight: 600 }}>{String(v)}</span>
          </div>
        ))}
        <div style={{ color: "var(--tc-text-muted)", marginTop: 4, fontSize: 9 }}>{rels.length} relation(s)</div>
      </div>
    );
  }, [hoverNode, graphData.links]);

  return (
    <div ref={containerRef} style={{ background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)", borderRadius: "var(--tc-radius-md)", padding: "16px", position: "relative" }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>Graphe d&apos;attaque</span>
        <div style={{ display: "flex", gap: 10, fontSize: 9 }}>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: 3, color: "var(--tc-text-muted)" }}>
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} /> {type}
            </span>
          ))}
        </div>
      </div>

      {loading && <div style={{ textAlign: "center", padding: "60px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Chargement du graphe...</div>}
      {!loading && graphData.nodes.length === 0 && <div style={{ textAlign: "center", padding: "60px 0", color: "var(--tc-text-muted)", fontSize: 12 }}>Aucune donnée. Lancez un test ou activez des connecteurs.</div>}

      {!loading && graphData.nodes.length > 0 && (
        <div style={{ position: "relative" }}>
          {tooltip}
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            width={dims.w} height={dims.h}
            backgroundColor="transparent"
            nodeCanvasObject={paintNode}
            nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
              ctx.beginPath(); ctx.arc(node.x, node.y, (node.val || 5) + 4, 0, Math.PI * 2); ctx.fillStyle = color; ctx.fill();
            }}
            linkCanvasObject={paintLink}
            linkDirectionalArrowLength={0}
            onNodeHover={(node: any) => setHoverNode(node || null)}
            onNodeClick={(node: any) => { if (graphRef.current) { graphRef.current.centerAt(node.x, node.y, 500); graphRef.current.zoom(2.5, 500); } }}
            d3AlphaDecay={0.01}
            d3VelocityDecay={0.3}
            cooldownTicks={200}
          />
          <div style={{ fontSize: 9, color: "var(--tc-text-muted)", marginTop: 6, textAlign: "center" }}>
            {graphData.nodes.length} noeuds · {graphData.links.length} relations — clic = zoom, molette = zoom, glisser = déplacer
          </div>
        </div>
      )}
    </div>
  );
}
