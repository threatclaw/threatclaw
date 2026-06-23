"use client";

// Per-incident attack graph (native DFIR, Phase 3). Renders the focused attack
// story for ONE incident — host root, forensic timeline as a chronological
// chain, lateral-movement branches — with cytoscape. Fed by /full's
// `attack_graph` ({nodes, edges}); no fetching here (parent owns the data).

import React, { useEffect, useRef } from "react";

export interface AttackGraphNode {
  id: string;
  label: string;
  kind: string; // host | process_spawn | net_connect | logon | ...
  severity: string;
  mitre: string | null;
}
export interface AttackGraphEdge {
  source: string;
  target: string;
  label: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "#903020",
  high: "#b0442a",
  medium: "#c08820",
  low: "#557",
  info: "#456",
};

export default function IncidentAttackGraph({
  nodes,
  edges,
}: {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current || nodes.length === 0) return;
    let cy: any = null;
    let cancelled = false;

    (async () => {
      const cytoscape = (await import("cytoscape")).default;
      if (cancelled || !ref.current) return;

      const cyNodes = nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.mitre ? `${n.label}\n[${n.mitre}]` : n.label,
          kind: n.kind,
          color: n.kind === "host" ? "#2a3550" : SEV_COLOR[n.severity] ?? "#456",
          shape: n.kind === "host" ? "round-rectangle" : "ellipse",
        },
      }));
      const cyEdges = edges.map((e, i) => ({
        data: {
          id: `e${i}`,
          source: e.source,
          target: e.target,
          label: e.label,
          lateral: e.label === "LATERAL" ? "yes" : "no",
        },
      }));

      cy = cytoscape({
        container: ref.current,
        elements: [...cyNodes, ...cyEdges],
        style: [
          {
            selector: "node",
            style: {
              "background-color": "data(color)",
              shape: "data(shape)",
              label: "data(label)",
              color: "#dfe3ea",
              "font-size": 9,
              "text-wrap": "wrap",
              "text-max-width": "120px",
              "text-valign": "center",
              "text-halign": "center",
              width: 26,
              height: 26,
              "border-width": 1,
              "border-color": "#0008",
            } as any,
          },
          {
            selector: 'node[kind="host"]',
            style: { width: 46, height: 30, "font-size": 10, "font-weight": "bold" } as any,
          },
          {
            selector: "edge",
            style: {
              width: 1.5,
              "line-color": "#5a6680",
              "target-arrow-color": "#5a6680",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              label: "data(label)",
              "font-size": 7,
              color: "#8a93a8",
            } as any,
          },
          {
            selector: 'edge[lateral="yes"]',
            style: { "line-style": "dashed", "line-color": "#b0442a", "target-arrow-color": "#b0442a" } as any,
          },
        ],
        layout: {
          name: "breadthfirst",
          directed: true,
          padding: 30,
          spacingFactor: 1.3,
          avoidOverlap: true,
        } as any,
      });
      cy.fit(undefined, 30);
    })();

    return () => {
      cancelled = true;
      if (cy) cy.destroy();
    };
  }, [nodes, edges]);

  if (nodes.length === 0) return null;
  return <div ref={ref} style={{ width: "100%", height: 320, background: "var(--tc-bg, #0b0e14)", borderRadius: 6 }} />;
}
