"use client";

// Left sidebar navigation for sectioned pages. Rendered by the root
// layout (app/layout.tsx) when the current pathname matches one of the
// sections declared in sections.ts — every page in a section gets the
// same nav for free, whether or not it uses PageShell.
//
// Visual language matches the SOC console: JetBrains Mono font, dense
// uppercase labels, red accent on the active item, NeuCard surface so
// the sidebar reads as a container rather than a floating list.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { sectionForPath, subNavLabel, type SubNavItem } from "./sections";

const SIDEBAR_WIDTH = 220;

export function SectionSidebar() {
  const pathname = usePathname() ?? "/";
  const locale = useLocale();
  const section = sectionForPath(pathname);

  // Query string is read client-side so the sidebar can highlight the
  // active tab-based sub-item (e.g. /setup?tab=agent) without pushing
  // the whole page into a Suspense boundary.
  const [query, setQuery] = useState("");
  useEffect(() => {
    const sync = () => setQuery(window.location.search.replace(/^\?/, ""));
    sync();
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, [pathname]);

  if (!section) return null;

  const currentFull = query ? `${pathname}?${query}` : pathname;

  const isActive = (href: string) => {
    const [targetPath, targetQs] = href.split("?", 2);
    if (pathname !== targetPath && !pathname.startsWith(targetPath + "/")) {
      return false;
    }
    if (!targetQs) {
      // For plain-path items, match only when there is no competing tab
      // query: we don't want /skills (no ?tab) to highlight when we're on
      // /skills?tab=catalog (another item handles that case).
      const activeItem = section.items.find((i) => {
        const [p, q] = i.href.split("?", 2);
        if (!q) return false;
        return (
          (pathname === p || pathname.startsWith(p + "/")) &&
          matchQuery(query, q)
        );
      });
      return !activeItem;
    }
    return matchQuery(query, targetQs);
  };

  return (
    <aside
      aria-label={`navigation ${section.key}`}
      style={{
        width: SIDEBAR_WIDTH,
        flex: `0 0 ${SIDEBAR_WIDTH}px`,
        borderRight: "1px solid var(--tc-border)",
        background: "var(--tc-surface-alt)",
        padding: "20px 0",
        position: "sticky",
        top: "72px",
        alignSelf: "flex-start",
        maxHeight: "calc(100vh - 72px)",
        overflowY: "auto",
      }}
    >
      <div
        style={{
          padding: "0 18px 12px",
          fontSize: "10px",
          fontWeight: 700,
          letterSpacing: "0.2em",
          textTransform: "uppercase",
          color: "var(--tc-text-muted)",
        }}
      >
        {section.label(locale)}
      </div>
      <nav style={{ display: "flex", flexDirection: "column", gap: "2px" }}>
        {section.items.map((item) => (
          <SidebarItem
            key={item.href}
            item={item}
            locale={locale}
            active={isActive(item.href)}
          />
        ))}
      </nav>
    </aside>
  );
}

function SidebarItem({
  item,
  locale,
  active,
}: {
  item: SubNavItem;
  locale: "fr" | "en";
  active: boolean;
}) {
  const Icon = item.icon;
  return (
    <Link
      href={item.href}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "10px 16px 10px 18px",
        fontSize: "12px",
        fontWeight: active ? 700 : 500,
        color: active ? "var(--tc-text)" : "var(--tc-text-sec)",
        background: active ? "var(--tc-input)" : "transparent",
        borderLeft: active
          ? "3px solid var(--tc-red)"
          : "3px solid transparent",
        textDecoration: "none",
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        transition: "background 120ms, color 120ms",
      }}
    >
      <Icon size={14} color={active ? "var(--tc-red)" : "var(--tc-text-muted)"} />
      <span>{subNavLabel(item, locale)}</span>
    </Link>
  );
}

function matchQuery(actual: string, target: string): boolean {
  const aq = new URLSearchParams(actual);
  const tq = new URLSearchParams(target);
  const keys: string[] = [];
  tq.forEach((_, k) => keys.push(k));
  for (const k of keys) {
    if (aq.get(k) !== tq.get(k)) return false;
  }
  return true;
}

/// Width constant exported so the root layout can reserve the gutter
/// via CSS grid without importing the component.
export const SECTION_SIDEBAR_WIDTH = SIDEBAR_WIDTH;
