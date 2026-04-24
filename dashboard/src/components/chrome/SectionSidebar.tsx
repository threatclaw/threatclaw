"use client";

// Unified left sidebar — single navigation component used across every
// sectioned page of the app. Rendered once by the root layout based on
// the current pathname + its section declared in sections.ts.
//
// Style is a direct lift of the original ConfigPage left rail because
// that's the look we're standardizing on: 11px JetBrains Mono, soft-red
// active state with red text + red left border, sober lowercase labels,
// full column height.

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

  // Query string is re-read on every URL change (pushState + popstate).
  // Without this, clicking a sidebar Link would change the URL but the
  // highlighted item would stay on the previous selection because
  // useEffect only fires once on mount.
  const [query, setQuery] = useState("");
  useEffect(() => {
    const sync = () => setQuery(window.location.search.replace(/^\?/, ""));
    sync();
    window.addEventListener("popstate", sync);

    // Hook into history.pushState/replaceState: Next.js Link navigations
    // don't emit popstate. We monkey-patch once and broadcast a custom
    // event so every SectionSidebar instance stays in sync.
    const w = window as unknown as {
      __tc_history_patched?: boolean;
      history: History;
    };
    if (!w.__tc_history_patched) {
      const origPush = w.history.pushState.bind(w.history);
      const origReplace = w.history.replaceState.bind(w.history);
      w.history.pushState = function (...args: Parameters<History["pushState"]>) {
        origPush(...args);
        window.dispatchEvent(new Event("tc:history"));
      } as typeof w.history.pushState;
      w.history.replaceState = function (...args: Parameters<History["replaceState"]>) {
        origReplace(...args);
        window.dispatchEvent(new Event("tc:history"));
      } as typeof w.history.replaceState;
      w.__tc_history_patched = true;
    }
    window.addEventListener("tc:history", sync);

    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("tc:history", sync);
    };
  }, [pathname]);

  if (!section) return null;

  const isActive = (href: string) => {
    const [targetPath, targetQs] = href.split("?", 2);
    if (pathname !== targetPath && !pathname.startsWith(targetPath + "/")) {
      return false;
    }
    if (!targetQs) {
      // Plain-path item: active only when no sibling tab-qualified item
      // is currently matched (so /skills doesn't light up when we're on
      // /skills?tab=catalog — that's another item's job).
      const tabScoped = section.items.some((i) => {
        const [p, q] = i.href.split("?", 2);
        if (!q) return false;
        return (
          (pathname === p || pathname.startsWith(p + "/")) && matchQuery(query, q)
        );
      });
      return !tabScoped;
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
        background: "var(--tc-surface)",
        padding: "20px 0",
        // Full-height column — stretches with the flex parent so the
        // border + background run down the whole page, not just to the
        // end of the list.
        alignSelf: "stretch",
        minHeight: "calc(100vh - 72px)",
        position: "sticky",
        top: "72px",
        overflowY: "auto",
        display: "flex",
        flexDirection: "column",
        fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
      }}
    >
      <div
        style={{
          fontSize: "9px",
          letterSpacing: "0.22em",
          color: "var(--tc-text-muted)",
          textTransform: "uppercase",
          padding: "0 18px 14px",
        }}
      >
        {section.label(locale)}
      </div>
      <nav style={{ display: "flex", flexDirection: "column" }}>
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
        width: "100%",
        padding: "9px 18px",
        background: active ? "var(--tc-red-soft)" : "transparent",
        color: active ? "var(--tc-red)" : "var(--tc-text-sec)",
        fontSize: "11px",
        fontWeight: active ? 700 : 500,
        textDecoration: "none",
        letterSpacing: "0.02em",
        textAlign: "left",
        borderLeft: active
          ? "2px solid var(--tc-red)"
          : "2px solid transparent",
        transition: "background 120ms, color 120ms",
      }}
      onMouseEnter={(e) => {
        if (!active) e.currentTarget.style.background = "var(--tc-input)";
      }}
      onMouseLeave={(e) => {
        if (!active) e.currentTarget.style.background = "transparent";
      }}
    >
      <Icon size={13} />
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

export const SECTION_SIDEBAR_WIDTH = SIDEBAR_WIDTH;
