"use client";

// Shared wrapper for every "content" page that is NOT the SOC console home.
// Gives every route the same gutters, maxWidth, font stack, and header
// pattern so the whole app reads as one product.
//
// When a page's pathname belongs to a section declared in sections.ts, a
// left sub-menu is automatically rendered on the left of the content.
// Pages don't need to know about this — the reverse lookup runs against
// usePathname() and drops out for pathnames with no section.
//
// The console home (/) has its own full-viewport layout and bypasses this
// shell on purpose.

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLocale } from "@/lib/useLocale";
import { sectionForPath, subNavLabel, type SubNavItem } from "./sections";

export function PageShell({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle?: string;
  right?: React.ReactNode;
  children: React.ReactNode;
}) {
  const pathname = usePathname() ?? "/";
  const locale = useLocale();
  const section = sectionForPath(pathname);
  // We read the query string directly off window instead of via
  // useSearchParams() — the hook forces the route into a Suspense
  // boundary for static prerender, which /exports and /skills would
  // otherwise hit at build time. Setting state on mount is enough for
  // our use case (highlighting the active sub-nav item).
  const [query, setQuery] = useState("");
  useEffect(() => {
    const update = () => setQuery(window.location.search.replace(/^\?/, ""));
    update();
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, [pathname]);

  return (
    <div
      style={{
        padding: "24px 28px 40px",
        fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
        color: "var(--tc-text)",
        maxWidth: "1600px",
        margin: "0 auto",
      }}
    >
      <div
        style={{
          marginBottom: "24px",
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "space-between",
          gap: "18px",
        }}
      >
        <div>
          <div
            style={{
              fontSize: "9px",
              letterSpacing: "0.22em",
              color: "var(--tc-text-muted)",
              textTransform: "uppercase",
            }}
          >
            {title}
          </div>
          {subtitle && (
            <div
              style={{
                fontSize: "13px",
                color: "var(--tc-text-sec)",
                marginTop: "6px",
                maxWidth: "700px",
                lineHeight: 1.5,
              }}
            >
              {subtitle}
            </div>
          )}
        </div>
        {right}
      </div>

      {section ? (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "180px 1fr",
            gap: "24px",
            alignItems: "start",
          }}
        >
          <SectionSideNav
            items={section.items}
            pathname={pathname}
            query={query}
            locale={locale}
          />
          <div style={{ minWidth: 0 }}>{children}</div>
        </div>
      ) : (
        children
      )}
    </div>
  );
}

function SectionSideNav({
  items,
  pathname,
  query,
  locale,
}: {
  items: SubNavItem[];
  pathname: string;
  query: string;
  locale: "fr" | "en";
}) {
  // Active-item detection splits href on '?' so an item that pins to
  // ?tab=agent highlights only when we're both on its path AND its tab.
  // Plain-path items match any query string on their path.
  const currentFull = query ? `${pathname}?${query}` : pathname;
  const isActive = (href: string) => {
    const [targetPath, targetQs] = href.split("?", 2);
    if (pathname !== targetPath && !pathname.startsWith(targetPath + "/")) {
      return false;
    }
    if (!targetQs) {
      return true;
    }
    const qs = new URLSearchParams(query);
    const target = new URLSearchParams(targetQs);
    const keys: string[] = [];
    target.forEach((_, k) => keys.push(k));
    for (const k of keys) {
      if (qs.get(k) !== target.get(k)) return false;
    }
    return true;
  };

  return (
    <nav
      aria-label="section"
      style={{
        position: "sticky",
        top: "16px",
        display: "flex",
        flexDirection: "column",
        gap: "2px",
        borderRight: "1px solid var(--tc-border)",
        paddingRight: "12px",
      }}
    >
      {items.map((item) => {
        const active = isActive(item.href);
        return (
          <Link
            key={item.href}
            href={item.href}
            style={{
              padding: "8px 10px",
              fontSize: "11px",
              fontWeight: active ? 700 : 500,
              color: active ? "var(--tc-text)" : "var(--tc-text-sec)",
              background: active ? "var(--tc-input)" : "transparent",
              borderLeft: active
                ? "2px solid var(--tc-red)"
                : "2px solid transparent",
              textDecoration: "none",
              textTransform: "uppercase",
              letterSpacing: "0.08em",
              borderRadius: "0 var(--tc-radius-sm) var(--tc-radius-sm) 0",
              transition: "background 120ms",
            }}
          >
            {subNavLabel(item, locale)}
          </Link>
        );
      })}
    </nav>
  );
}
