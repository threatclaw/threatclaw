"use client";

// Experimental frontend playground.
//
// Lives under /dash-test — not linked from the main TopNav on purpose.
// Use this route to iterate on a new UX without touching the current
// dashboard at /. When a design is validated, promote it by moving
// its files over the existing routes.
//
// Important: this layout intentionally does NOT render <TopNav />. That
// way the experimental route can explore a completely different chrome
// (sidebar, split-pane, command palette, whatever) without interference
// from the legacy top navigation. Auth and environment banner still
// apply because they live in the root layout above this one.

import React from "react";

export default function DashTestLayout({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        // Break out of the 1100px maxWidth set by the root layout so
        // the experimental frontend can use the full viewport if it
        // wants (typical for sidebar-first layouts).
        position: "relative",
        left: "50%",
        right: "50%",
        marginLeft: "-50vw",
        marginRight: "-50vw",
        width: "100vw",
        minHeight: "calc(100vh - 44px)",
        background: "var(--tc-bg)",
      }}
    >
      {children}
    </div>
  );
}
