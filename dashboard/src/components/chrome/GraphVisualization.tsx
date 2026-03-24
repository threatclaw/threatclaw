"use client";

import React, { useRef, useEffect, useState, useCallback } from "react";

interface GraphNode {
  id: string;
  label: string;
  type: "ip" | "asset" | "cve" | "technique" | "actor" | "campaign";
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GraphEdge {
  source: string;
  target: string;
  label: string;
}

const NODE_COLORS: Record<string, string> = {
  ip: "#d03020",
  asset: "#3080d0",
  cve: "#d09020",
  technique: "#9060d0",
  actor: "#d06020",
  campaign: "#30a050",
};

const NODE_RADIUS: Record<string, number> = {
  ip: 8, asset: 10, cve: 7, technique: 6, actor: 9, campaign: 8,
};

export default function GraphVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [hovered, setHovered] = useState<GraphNode | null>(null);
  const [dragging, setDragging] = useState<GraphNode | null>(null);
  const animRef = useRef<number>(0);
  const nodesRef = useRef<GraphNode[]>([]);

  // Fetch graph data
  const loadGraph = useCallback(async () => {
    setLoading(true);
    try {
      // Fetch IPs, assets, CVEs from the graph
      const [ipsRes, assetsRes] = await Promise.all([
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (ip:IP)-[a:ATTACKS]->(asset:Asset) RETURN ip.addr, asset.hostname, asset.id, a.method LIMIT 50" }),
        }),
        fetch("/api/tc/graph/query", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cypher: "MATCH (c:CVE)-[:AFFECTS]->(a:Asset) RETURN c.id, a.id, a.hostname LIMIT 30" }),
        }),
      ]);

      const ipsData = await ipsRes.json();
      const assetsData = await assetsRes.json();

      const nodeMap = new Map<string, GraphNode>();
      const edgeList: GraphEdge[] = [];
      const W = 600, H = 400;

      // Process attack edges
      for (const r of (ipsData.results || [])) {
        const ipAddr = r["ip.addr"] || "";
        const assetId = r["asset.id"] || r["asset.hostname"] || "";
        const method = r["a.method"] || "attacks";

        if (ipAddr && !nodeMap.has(ipAddr)) {
          nodeMap.set(ipAddr, {
            id: ipAddr, label: ipAddr, type: "ip",
            x: Math.random() * W, y: Math.random() * H, vx: 0, vy: 0,
          });
        }
        if (assetId && !nodeMap.has(assetId)) {
          nodeMap.set(assetId, {
            id: assetId, label: r["asset.hostname"] || assetId, type: "asset",
            x: W / 2 + (Math.random() - 0.5) * 200, y: H / 2 + (Math.random() - 0.5) * 200, vx: 0, vy: 0,
          });
        }
        if (ipAddr && assetId) {
          edgeList.push({ source: ipAddr, target: assetId, label: method });
        }
      }

      // Process CVE edges
      for (const r of (assetsData.results || [])) {
        const cveId = r["c.id"] || "";
        const assetId = r["a.id"] || r["a.hostname"] || "";

        if (cveId && !nodeMap.has(cveId)) {
          nodeMap.set(cveId, {
            id: cveId, label: cveId, type: "cve",
            x: Math.random() * W, y: Math.random() * H, vx: 0, vy: 0,
          });
        }
        if (assetId && !nodeMap.has(assetId)) {
          nodeMap.set(assetId, {
            id: assetId, label: r["a.hostname"] || assetId, type: "asset",
            x: W / 2 + (Math.random() - 0.5) * 200, y: H / 2 + (Math.random() - 0.5) * 200, vx: 0, vy: 0,
          });
        }
        if (cveId && assetId) {
          edgeList.push({ source: cveId, target: assetId, label: "affects" });
        }
      }

      const nodeList = Array.from(nodeMap.values());
      setNodes(nodeList);
      setEdges(edgeList);
      nodesRef.current = nodeList;
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { loadGraph(); }, [loadGraph]);

  // Force-directed simulation
  useEffect(() => {
    if (nodes.length === 0) return;

    const W = 600, H = 400;
    const nodesCopy = [...nodes];
    nodesRef.current = nodesCopy;

    const tick = () => {
      const ns = nodesRef.current;
      const damping = 0.92;
      const repulsion = 800;
      const attraction = 0.005;
      const centerForce = 0.01;

      // Repulsion between all nodes
      for (let i = 0; i < ns.length; i++) {
        for (let j = i + 1; j < ns.length; j++) {
          const dx = ns[j].x - ns[i].x;
          const dy = ns[j].y - ns[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = repulsion / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          ns[i].vx -= fx; ns[i].vy -= fy;
          ns[j].vx += fx; ns[j].vy += fy;
        }
      }

      // Attraction along edges
      for (const e of edges) {
        const src = ns.find(n => n.id === e.source);
        const tgt = ns.find(n => n.id === e.target);
        if (!src || !tgt) continue;
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const fx = dx * attraction;
        const fy = dy * attraction;
        src.vx += fx; src.vy += fy;
        tgt.vx -= fx; tgt.vy -= fy;
      }

      // Center gravity
      for (const n of ns) {
        n.vx += (W / 2 - n.x) * centerForce;
        n.vy += (H / 2 - n.y) * centerForce;
      }

      // Update positions
      for (const n of ns) {
        if (dragging && n.id === dragging.id) continue;
        n.vx *= damping; n.vy *= damping;
        n.x += n.vx; n.y += n.vy;
        n.x = Math.max(20, Math.min(W - 20, n.x));
        n.y = Math.max(20, Math.min(H - 20, n.y));
      }

      // Draw
      const canvas = canvasRef.current;
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      const dpr = window.devicePixelRatio || 1;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      ctx.scale(dpr, dpr);

      // Clear
      ctx.clearRect(0, 0, W, H);

      // Edges
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(255,255,255,0.1)";
      for (const e of edges) {
        const src = ns.find(n => n.id === e.source);
        const tgt = ns.find(n => n.id === e.target);
        if (!src || !tgt) continue;
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.stroke();
      }

      // Nodes
      for (const n of ns) {
        const r = NODE_RADIUS[n.type] || 8;
        const color = NODE_COLORS[n.type] || "#888";
        const isHov = hovered?.id === n.id;

        // Glow
        if (isHov) {
          ctx.beginPath();
          ctx.arc(n.x, n.y, r + 4, 0, Math.PI * 2);
          ctx.fillStyle = color + "40";
          ctx.fill();
        }

        // Circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = isHov ? "#fff" : color + "80";
        ctx.lineWidth = isHov ? 2 : 1;
        ctx.stroke();

        // Label
        ctx.fillStyle = "rgba(255,255,255,0.7)";
        ctx.font = "9px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText(n.label.substring(0, 20), n.x, n.y + r + 12);
      }

      // Hovered tooltip
      if (hovered) {
        const n = ns.find(nd => nd.id === hovered.id);
        if (n) {
          ctx.fillStyle = "rgba(0,0,0,0.8)";
          ctx.roundRect(n.x + 15, n.y - 15, Math.max(n.label.length * 7, 80), 24, 4);
          ctx.fill();
          ctx.fillStyle = "#fff";
          ctx.font = "11px Inter, sans-serif";
          ctx.textAlign = "left";
          ctx.fillText(`${n.type.toUpperCase()}: ${n.label}`, n.x + 20, n.y + 2);
        }
      }

      animRef.current = requestAnimationFrame(tick);
    };

    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes, edges, hovered, dragging]);

  // Mouse interaction
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;

    if (dragging) {
      const n = nodesRef.current.find(nd => nd.id === dragging.id);
      if (n) { n.x = mx; n.y = my; n.vx = 0; n.vy = 0; }
      return;
    }

    const found = nodesRef.current.find(n => {
      const r = NODE_RADIUS[n.type] || 8;
      return Math.sqrt((n.x - mx) ** 2 + (n.y - my) ** 2) < r + 4;
    });
    setHovered(found || null);
  }, [dragging]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (hovered) { setDragging(hovered); e.preventDefault(); }
  }, [hovered]);

  const handleMouseUp = useCallback(() => { setDragging(null); }, []);

  return (
    <div style={{
      background: "var(--tc-surface-alt)", border: "1px solid var(--tc-border)",
      borderRadius: "var(--tc-radius-card)", padding: "16px", position: "relative",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "10px" }}>
        <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--tc-text)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Graphe d&apos;attaque
        </span>
        <div style={{ display: "flex", gap: "10px", fontSize: "9px" }}>
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <span key={type} style={{ display: "flex", alignItems: "center", gap: "3px", color: "var(--tc-text-muted)" }}>
              <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: color, display: "inline-block" }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      {loading && (
        <div style={{ textAlign: "center", padding: "60px 0", color: "var(--tc-text-muted)", fontSize: "12px" }}>
          Chargement du graphe...
        </div>
      )}

      {!loading && nodes.length === 0 && (
        <div style={{ textAlign: "center", padding: "60px 0", color: "var(--tc-text-faint)", fontSize: "12px" }}>
          Aucune donnee dans le graphe. Lancez un test ou activez des connecteurs.
        </div>
      )}

      {!loading && nodes.length > 0 && (
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: "400px", cursor: dragging ? "grabbing" : hovered ? "grab" : "default" }}
          onMouseMove={handleMouseMove}
          onMouseDown={handleMouseDown}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        />
      )}

      {!loading && nodes.length > 0 && (
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: "8px", fontSize: "10px", color: "var(--tc-text-muted)" }}>
          <span>{nodes.length} noeuds &middot; {edges.length} relations</span>
          <span>Glissez les noeuds pour reorganiser</span>
        </div>
      )}
    </div>
  );
}
